/**
 * OpenID Connect Core: Dynamic Certification Profile, OP tests (upstream openid/OIDCCDynamicTestPlan.java).
 *
 * The plan registers its clients dynamically and uses discovery. Most modules need private_key_jwt client
 * authentication (the registration with a jwks_uri, the refresh token with a rotated RP key), so the plan fixes it for
 * them; the user selects the response_type (CONFORMANCE_VARIANT or the CI project).
 *
 *   CONFORMANCE_PROJECT=op-dynamic pnpm test tests/op/dynamic.spec.ts
 */
import * as authz from "../../src/op/authorization.ts";
import * as discovery from "../../src/op/discovery.ts";
import * as discoveryEndpoint from "../../src/op/discovery-endpoint.ts";
import {
	checkErrorDescriptionContainsCRLFTAB,
	ensureContentTypeApplicationJwt,
	ensureContentTypeJson,
	ensureHttpStatusCodeIs200,
	ensureHttpStatusCodeIs400,
	validateErrorDescription,
	validateErrorUri,
} from "../../src/op/endpoint.ts";
import * as idToken from "../../src/op/id-token.ts";
import * as jwks from "../../src/op/jwks.ts";
import type { Op, RegistrationOp } from "../../src/op/op.ts";
import * as refresh from "../../src/op/refresh-token.ts";
import * as registration from "../../src/op/registration.ts";
import type { ClientKeys, RegisteredClient } from "../../src/op/registration.ts";
import * as requestObject from "../../src/op/request-object.ts";
import * as token from "../../src/op/token.ts";
import * as userinfo from "../../src/op/userinfo.ts";
import { block, logModule, soft } from "../../src/suite/conditions.ts";
import type { Jwks } from "../../src/suite/jose.ts";
import { waitForJWKSRefreshDelay } from "../../src/suite/wait.ts";
import { skipTest, test } from "../fixtures.ts";
import {
	completeCodeFlow,
	oidccDiscoveryEndpointVerification,
	oidccEnsureRequestObjectWithRedirectUri,
	oidccIdTokenUnsigned,
	oidccRefreshToken,
	oidccServer,
	skipIfNoneUnsupported,
	userinfoEndpointTests,
} from "./shared.ts";

const PLAN = "oidcc-dynamic-certification-test-plan";

/**
 * upstream variantPrivateKeyJwtDynReg: "most tests it doesn't matter what client auth is used, but private_key_jwt is
 * required for [at least] OIDCCRegistrationJwksUri, OIDCCRefreshTokenRPKeyRotation"
 */
const privateKeyJwtDynReg = {
	server_metadata: "discovery",
	client_auth_type: "private_key_jwt",
	client_registration: "dynamic_client",
	response_mode: "default",
};

/**
 * The OP's keys, fetched and checked as loadServerKeys() does, except that an invalid key set is a FAILURE here
 * (upstream: OIDCCServerRotateKeys.fetchAndValidateJwks)
 */
async function fetchAndValidateJwks(metadata: discovery.ServerMetadata): Promise<Jwks> {
	const keys = await jwks.fetchServerKeys(metadata);
	soft(() => jwks.checkServerKeysIsValid(keys));
	await jwks.validateJwks(keys, "server JWKS", { requirements: ["RFC7517-1.1"] });
	soft(() => jwks.checkForKeyIdInServerJWKs(keys, "OIDCC-10.1"));
	soft(() => jwks.checkDistinctKeyIdValueInServerJWKs(keys, "RFC7517-4.5"));
	return keys;
}

/**
 * Sends the browser to the authorization endpoint to check the appearance of the login page (the browser automation
 * screenshots it); a callback is not needed for the test.
 *
 * upstream: AbstractOIDCCDynamicRegistrationTest.performAuthorizationFlow (logo_uri, policy_uri, tos_uri)
 */
async function checkLoginPage(
	op: RegistrationOp,
	client: RegisteredClient,
	expectScreenshot: (...requirements: string[]) => string,
): Promise<void> {
	const { request, placeholder } = await block("Make request to authorization endpoint", () => ({
		request: authz.createAuthorizationRequest(op, client.client),
		placeholder: expectScreenshot("OIDCR-2"),
	}));
	const response = await authz.authorizeExpectingErrorPageOrRedirect(op, request, placeholder);
	if (response != null) {
		// upstream: AbstractOIDCCDynamicRegistrationTest.processCallback
		// We're not expecting a callback, but we need to handle any potential error response
		authz.checkCallbackLocation(request, response);
		authz.checkIfAuthorizationEndpointError(response);
		logModule(
			"Received a callback from the authorization endpoint. It is not necessary to complete login for this test.",
		);
	}
}

/** The request_uri the client registered (created while the suite built the registration request) */
function suiteRequestUri(requestUri: requestObject.RequestUri | null): requestObject.RequestUri {
	if (requestUri == null) {
		throw new Error("The request_uri was not created: the client was not registered by the suite");
	}
	return requestUri;
}

/** The suite serves the request object at the request_uri (upstream: AbstractOIDCCRequestUriServerTest.handleHttp) */
function serveRequestObject(op: Op, requestUri: requestObject.RequestUri, requestObjectJwt: string): void {
	op.server.on(
		requestUri.path,
		() => new Response(requestObjectJwt, { status: 200, headers: { "content-type": "application/jwt" } }),
	);
}

/**
 * The suite serves the client's public keys at the client's jwks_uri (upstream: handleHttp "client1_jwks"); `keys()`
 * is the current set, rotated keys included.
 */
function serveClientJwks(op: Op, keys: () => ClientKeys | null): void {
	op.server.on("client1_jwks", () => {
		const current = keys();
		return current == null
			? new Response(
					"jwks endpoint called before key exists - please wait for test to initialise before calling client jwks endpoint",
					{ status: 500 },
				)
			: Response.json(current.publicJwks);
	});
}

test.describe(PLAN, () => {
	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: privateKeyJwtDynReg } });

		// upstream: openid/OIDCCIdTokenRS256.java (OP-IDToken-kid, OP-IDToken-RS256)
		test("oidcc-idtoken-rs256: an id_token requested with RS256 is signed with RS256 and names its key", async ({
			op,
			configureClient,
		}) => {
			const client = await configureClient({
				customize: registration.addIdTokenSigningAlgRS256ToDynamicRegistrationRequest,
			});

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client),
			);
			const response = await authz.authorize(op, request);
			await completeCodeFlow(op, client, request, response, {
				performIdTokenValidation: async (signed) => {
					// OP-IDToken-kid
					// OIDCC-10.1 seems to only require a KID if the server has multiple JWKs, but we'll replicate the python
					// test here and require it always.
					soft(() => idToken.ensureIdTokenContainsKid(signed, "OIDCC-10.1"));
					// OP-IDToken-RS256
					soft(() => idToken.checkIdTokenSignatureAlgorithm(signed, client.registrationRequest ?? {}, "OIDCC-3.1.3.7"));
					await idToken.performStandardIdTokenChecks(op, client.client, request, signed);
				},
			});
		});

		// upstream: openid/OIDCCIdTokenUnsigned.java (OP-IDToken-none)
		test(
			"oidcc-idtoken-unsigned: an id_token requested with alg none is returned unsigned, or the test is skipped when the OP does not support none",
			oidccIdTokenUnsigned,
		);

		// upstream: openid/OIDCCUserInfoRS256.java (OP-UserInfo-RS256)
		test("oidcc-userinfo-rs256: the userinfo response is a JWT signed with RS256 when the client registered for it", async ({
			op,
			configureClient,
		}) => {
			const client = await configureClient({
				customize: (req) => registration.addUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest(req, "OIDCR-2"),
			});
			soft(() =>
				discoveryEndpoint.checkDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256(op.metadata, "OIDCD-3"),
			);

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client),
			);
			const response = await authz.authorize(op, request);
			const tokens = await completeCodeFlow(op, client, request, response);

			// upstream: AbstractOIDCCUserInfoTest.onPostAuthorizationFlowComplete
			const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
			soft(() => ensureHttpStatusCodeIs200(res));
			// extractUserInfoResponse of the signed variant
			soft(() => ensureContentTypeApplicationJwt(res, "OIDCC-5.3.2"));
			// should probably also use AbstractVerifyJwsSignatureUsingKid at some point
			await soft(() => userinfo.validateUserInfoResponseSignature(res, op.jwks, "OIDCC-5.3.2"));
			const { userinfoObject, userinfo: claims } =
				await userinfo.extractSignedUserInfoFromUserInfoEndpointResponse(res);
			soft(() => userinfo.validateUserInfoSigningAlgIsRS256(userinfoObject));
			// This is just a warning since https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse is fairly
			// lax on what is required
			soft(
				() =>
					userinfo.validateSignedUserInfoResponseStandardJWTClaims(
						userinfoObject,
						op.metadata,
						client.client,
						"OIDCC-5.3.2",
					),
				"warning",
			);
			// This is not a 'must not' in the spec, but equally including nonce here is almost certainly a mistake by the
			// implementor there is nothing in the spec that suggests including nonce
			soft(() => userinfo.ensureUserInfoDoesNotContainNonce(claims, "OIDCC-5.3.2", "OIDCC-5.1"));
			userinfo.validateExtractedUserInfoResponse(claims);
		});

		// upstream: openid/OIDCCEnsureRedirectUriInAuthorizationRequest.java (OP-redirect_uri-Missing)
		test("oidcc-ensure-redirect-uri-in-authorization-request: a request without redirect_uri is answered with an error page, not a redirect", async ({
			op,
			configureClient,
		}) => {
			const client = await configureClient({
				customize: (req) => registration.addMultipleRedirectUriToDynamicRegistrationRequest(req, op.redirectUri),
			});
			discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

			const { request, placeholder } = await block("Make request to authorization endpoint", () => ({
				request: authz.createAuthorizationRequest(op, client.client, {
					steps: authz.removeRedirectUriFromAuthorizationEndpointRequest,
				}),
				placeholder: authz.expectRedirectUriMissingErrorPage("OIDCC-3.1.2.1"),
			}));
			const response = await authz.authorizeExpectingErrorPageOrRedirect(op, request, placeholder);
			if (response != null) {
				await block("Verify authorization endpoint response", () => {
					authz.checkCallbackLocation(request, response);
					soft(() => authz.authorizationEndpointRedirectedBackUnexpectedly());
				});
			}
		});

		// upstream: openid/OIDCCRedirectUriQueryOK.java (OP-redirect_uri-Query-OK)
		test("oidcc-redirect-uri-query-OK: a redirect_uri with the registered query component completes the authorization", async ({
			op,
			configureClient,
		}) => {
			const redirectUri = registration.addQueryToRedirectUri(op.redirectUri);
			const client = await configureClient({ redirectUri });
			// the registered redirect_uri is the one of the authorization and the token request
			const queryOp = { ...op, redirectUri };

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(queryOp, client.client),
			);
			const response = await authz.authorize(queryOp, request);
			await completeCodeFlow(queryOp, client, request, response);
		});

		// upstream: openid/OIDCCRedirectUriQueryMismatch.java (OP-redirect_uri-Query-Mismatch)
		test("oidcc-redirect-uri-query-mismatch: a redirect_uri whose query differs from the registered one is rejected with an error page", async ({
			op,
			configureClient,
		}) => {
			const redirectUri = registration.addQueryToRedirectUri(op.redirectUri);
			const client = await configureClient({ redirectUri });
			const queryOp = { ...op, redirectUri };
			discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

			const { request, placeholder } = await block("Make request to authorization endpoint", () => ({
				request: authz.createAuthorizationRequest(queryOp, client.client, {
					steps: authz.replaceRedirectUriQueryInAuthorizationRequest,
				}),
				placeholder: authz.expectRedirectUriErrorPage("OIDCC-3.1.2.1"),
			}));
			const response = await authz.authorizeExpectingErrorPageOrRedirect(queryOp, request, placeholder);
			if (response != null) {
				throw new Error(
					"The authorization server called the registered redirect uri. This should not have happened as the client provided a bad redirect_uri in the request.",
				);
			}
		});

		// upstream: openid/OIDCCRedirectUriQueryAdded.java (OP-redirect_uri-Query-Added)
		test("oidcc-redirect-uri-query-added: a redirect_uri with a query when none is registered is rejected with an error page", async ({
			op,
			client,
		}) => {
			discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

			const { request, placeholder } = await block("Make request to authorization endpoint", () => ({
				request: authz.createAuthorizationRequest(op, client.client, {
					steps: authz.addQueryToRedirectUriInAuthorizationRequest,
				}),
				placeholder: authz.expectRedirectUriErrorPage("OIDCC-3.1.2.1"),
			}));
			const response = await authz.authorizeExpectingErrorPageOrRedirect(op, request, placeholder);
			if (response != null) {
				throw new Error(
					"The authorization server called the registered redirect uri. This should not have happened as the client provided a bad redirect_uri in the request.",
				);
			}
		});

		// upstream: openid/OIDCCRedirectUriRegFrag.java (OP-redirect_uri-RegFrag)
		test("oidcc-redirect-uri-regfrag: a registration with a redirect_uri containing a fragment is rejected", async ({
			registrationOp: op,
		}) => {
			const redirectUri = registration.addFragmentToRedirectUri(op.redirectUri);
			const { clientName, initialAccessToken } = registration.extractDynamicRegistrationSettings(op.config);

			const { request } = await registration.createDynamicClientRegistrationRequest(op.testId, {
				clientName,
				responseType: op.variant.response_type,
				clientAuthType: op.variant.client_auth_type,
				redirectUri,
			});
			const response = await registration.callDynamicRegistrationEndpoint(
				op.metadata,
				request,
				initialAccessToken,
				"RFC6749-3.1.2",
			);
			soft(() => ensureContentTypeJson(response));
			soft(() => ensureHttpStatusCodeIs400(response));
			soft(
				() =>
					registration.checkErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata(
						response,
						"OIDCR-3.3",
					),
				"warning",
			);
		});
	});

	test.describe(() => {
		// the discovery document is checked whatever the clients use
		test.use({
			plan: { name: PLAN, variant: { server_metadata: "discovery", client_registration: "dynamic_client" } },
		});

		// upstream: openid/OIDCCDiscoveryEndpointVerification.java (OP-Discovery-Config)
		test(
			"oidcc-discovery-endpoint-verification: the discovery document is served as JSON and has the metadata the specifications require",
			oidccDiscoveryEndpointVerification,
		);
	});

	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: privateKeyJwtDynReg } });

		// upstream: openid/OIDCCServerTest.java (OP-Registration-Endpoint, OP-Registration-Dynamic, OP-Registration-jwks)
		test(
			"oidcc-server: the code flow returns a valid code, tokens and id_token, and the access token works at userinfo",
			oidccServer,
		);

		// upstream: openid/OIDCCRegistrationLogoUri.java (OP-Registration-logo_uri)
		test("oidcc-registration-logo-uri: a client registered with a logo_uri gets a login page showing the logo", async ({
			registrationOp: op,
			configureClient,
		}) => {
			const logoUri = registration.createLogoUri(op.baseUrl);
			const client = await configureClient({
				customize: (req) => registration.addLogoUriToDynamicRegistrationRequest(req, logoUri),
				checkClientAuthSupported: false,
			});

			await checkLoginPage(op, client, registration.expectLoginPageWithLogo);
		});

		// upstream: openid/OIDCCRegistrationPolicyUri.java (OP-Registration-policy_uri)
		test("oidcc-registration-policy-uri: a client registered with a policy_uri gets a login page linking to the policy", async ({
			registrationOp: op,
			configureClient,
		}) => {
			const policyUri = registration.createPolicyUri(op.baseUrl);
			const client = await configureClient({
				customize: (req) => registration.addPolicyUriToDynamicRegistrationRequest(req, policyUri),
				checkClientAuthSupported: false,
			});

			await checkLoginPage(op, client, registration.expectLoginPageWithPolicyLink);
		});

		// upstream: openid/OIDCCRegistrationTosUri.java (OP-Registration-tos_uri)
		test("oidcc-registration-tos-uri: a client registered with a tos_uri gets a login page linking to the terms of service", async ({
			registrationOp: op,
			configureClient,
		}) => {
			const tosUri = registration.createTosUri();
			const client = await configureClient({
				customize: (req) => registration.addTosUriToDynamicRegistrationRequest(req, tosUri),
				checkClientAuthSupported: false,
			});

			await checkLoginPage(op, client, registration.expectLoginPageWithTosLink);
		});

		// upstream: openid/OIDCCRegistrationJwksUri.java (OP-Registration-jwks_uri)
		test("oidcc-registration-jwks-uri: a client registered with a jwks_uri authenticates with keys the OP fetches from it", async ({
			op,
			configureClient,
		}) => {
			let clientKeys: ClientKeys | null = null;
			serveClientJwks(op, () => clientKeys);
			const client = await configureClient({
				jwksUri: registration.createJwksUri(op.baseUrl),
				generateKeys: async () => (clientKeys = await registration.generateRS256ClientJWKsWithKeyID()),
			});

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client),
			);
			const response = await authz.authorize(op, request);
			await completeCodeFlow(op, client, request, response);
		});

		// upstream: openid/OIDCCRegistrationSectorUri.java
		test("oidcc-registration-sector-uri: a registration with a sector_identifier_uri listing the redirect_uri is accepted", async ({
			registrationOp: op,
			configureClient,
		}) => {
			const subjectTypesSupported = op.metadata["subject_types_supported"];
			if (!Array.isArray(subjectTypesSupported) || !subjectTypesSupported.includes("pairwise")) {
				skipTest("Server configuration does not explicitly support pairwise subject type");
			}
			const sectorRedirectUris = registration.createSectorRedirectUris(op.redirectUri);
			// the suite serves the sector identifier document (upstream: handleHttp "redirect_uris.json")
			op.server.on("redirect_uris.json", () => Response.json(sectorRedirectUris));

			await configureClient({
				customize: (req) => {
					registration.addSubjectTypePairwiseToDynamicRegistrationRequest(req);
					registration.addSectorIdentifierUriToDynamicRegistrationRequest(req, op.baseUrl);
				},
				checkClientAuthSupported: false,
			});
			// Don't need to test authorization here.
		});

		// upstream: openid/OIDCCRegistrationSectorBad.java (OP-Registration-Sector-Bad)
		test("oidcc-registration-sector-bad: a registration whose sector_identifier_uri does not list the redirect_uri is rejected", async ({
			registrationOp: op,
		}) => {
			const subjectTypesSupported = op.metadata["subject_types_supported"];
			if (!Array.isArray(subjectTypesSupported) || !subjectTypesSupported.includes("pairwise")) {
				skipTest("Server configuration does not explicitly support pairwise subject type");
			}
			const { clientName, initialAccessToken } = registration.extractDynamicRegistrationSettings(op.config);

			const sectorRedirectUris = registration.createInvalidSectorRedirectUris();
			op.server.on("redirect_uris.json", () => Response.json(sectorRedirectUris));

			const { request } = await registration.createDynamicClientRegistrationRequest(op.testId, {
				clientName,
				responseType: op.variant.response_type,
				clientAuthType: op.variant.client_auth_type,
				redirectUri: op.redirectUri,
				customize: (req) => {
					registration.addSubjectTypePairwiseToDynamicRegistrationRequest(req);
					registration.addSectorIdentifierUriToDynamicRegistrationRequest(req, op.baseUrl);
				},
			});
			const response = await registration.callDynamicRegistrationEndpoint(
				op.metadata,
				request,
				initialAccessToken,
				"OIDCR-5",
			);
			soft(() => ensureContentTypeJson(response));
			soft(() => ensureHttpStatusCodeIs400(response));
			soft(
				() => registration.checkErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata(response, "OIDCR-3.3"),
				"warning",
			);
			// No authorization flow in this test
		});
	});

	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: { server_metadata: "discovery" } } });

		// upstream: openid/OIDCCServerRotateKeys.java (OP-Rotation-OP-Sig)
		// The upstream module waits for the user to rotate the OP's keys and press 'Start'; in an unattended run it
		// starts right away (as upstream's CI does), so the OP's keys are compared before and after nothing happened.
		test("oidcc-server-rotate-keys: the OP's jwks_uri has a new signing key after a rotation and still has the old one", async ({
			conformance,
			variant,
		}) => {
			const { config } = conformance;
			const metadata =
				variant.server_metadata === "static"
					? discovery.getStaticServerConfiguration(config)
					: (await discovery.getDynamicServerConfiguration(config)).metadata;
			// make sure the server configuration passes some basic sanity checks
			discovery.checkServerConfiguration(metadata);

			const originalJwks = await block("Fetch & validate current server keys", () => fetchAndValidateJwks(metadata));
			jwks.tellUserToRotateOpKeys();
			conformance.log.log("TEST-RUNNER", {
				msg: "Starting the test module without waiting for the user to press 'Start' (unattended run)",
				result: "INFO",
			});

			const newJwks = await block("Fetch & validate new server keys", () => fetchAndValidateJwks(metadata));
			// note that we don't actually check if the server now uses the new key to sign id_tokens (same as python)
			soft(() => jwks.verifyNewJwksHasNewSigningKey(originalJwks, newJwks, "OIDCC-10.1.1"));
			// the python suite did not check this
			soft(() => jwks.verifyNewJwksStillHasOldSigningKey(originalJwks, newJwks, "OIDCC-10.1.1"), "warning");
		});
	});

	test.describe(() => {
		test.use({ plan: { name: PLAN, variant: privateKeyJwtDynReg } });

		// upstream: openid/OIDCCRefreshTokenRPKeyRotation.java (OP-Rotation-RP-Sig)
		test("oidcc-refresh-token-rp-key-rotation: a refresh token is accepted with a client assertion signed by a rotated RP key", async ({
			op,
			configureClient,
		}) => {
			let clientKeys: ClientKeys | null = null;
			serveClientJwks(op, () => clientKeys);
			const client = await configureClient({
				jwksUri: registration.createJwksUri(op.baseUrl),
				generateKeys: async () => (clientKeys = await registration.generateRS256ClientJWKsWithKeyID()),
				customize: registration.addRefreshTokenGrantTypeToDynamicRegistrationRequest,
				completeClientConfiguration: (_, configured) =>
					registration.setScopeInClientConfigurationToOpenIdOfflineAccess(configured),
			});

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client, {
					steps: (params) =>
						authz.addPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess(params, "OIDCC-11"),
				}),
			);
			const response = await authz.authorize(op, request);
			const tokens = await block("Verify authorization endpoint response", async () => {
				authz.checkAuthorizationResponse(op, request, response);
				const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
				const tokenRequest = await token.createAuthorizationCodeRequest(op, client, code);
				const result = await token.requestAuthorizationCode(op, client, tokenRequest);
				await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
				return result;
			});

			const rotatedKeys = await block("Cycling keys in RP jwks_uri", () =>
				registration.generateRS256ClientJWKsWithKeyID(),
			);
			clientKeys = rotatedKeys;
			await block(
				"Waiting, so that any DoS limits on retrieving the jwks_uri too often are not triggered",
				// the python test does not have this wait, which causes the python test to fail against node oidc provider
				// and Authlete as it hits limits on how frequently jwks_uri is retrieved - the sleep avoids this. It may be
				// decreased via the 'jwks_refresh_delay' server configuration property.
				() => waitForJWKSRefreshDelay(op.config),
			);

			// upstream: sendRefreshTokenRequestAndCheckIdTokenClaims
			const refreshToken = refresh.extractRefreshTokenFromTokenResponse(tokens.response);
			soft(() => discovery.ensureServerConfigurationSupportsRefreshToken(op.metadata, "OIDCD-3"), "warning");
			soft(() => refresh.ensureRefreshTokenContainsAllowedCharactersOnly(tokens.response, "RFC6749-A.17"));
			const refreshed = await block("Refresh Token Request", () =>
				refresh.refreshTokenRequestSteps(op, { ...client, keys: rotatedKeys }, refreshToken, tokens, {
					secondClient: false,
				}),
			);

			await userinfoEndpointTests(op, refreshed.accessToken);
		});

		// https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_request_uri_Unsigned
		// upstream: openid/OIDCCRequestUriUnsigned.java (OP-request_uri-Unsigned-Dynamic)
		test("oidcc-request-uri-unsigned: an authorization request passing an unsigned request object by reference completes", async ({
			op,
			configureClient,
		}) => {
			let requestUri: requestObject.RequestUri | null = null;
			const client = await configureClient({
				customize: (req) => {
					requestUri = requestObject.createRandomRequestUriWithFragment(op.baseUrl, "OIDCC-6.2");
					registration.addRequestUriToDynamicRegistrationRequest(req, requestUri.fullUrl);
				},
			});
			soft(() => discovery.checkDiscEndpointRequestUriParameterSupported(op.metadata, "OIDCD-3"));
			skipIfNoneUnsupported(op);
			const uri = suiteRequestUri(requestUri);

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client, {
					buildRedirect: (_, params) => {
						const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(params);
						const requestObjectJwt = requestObject.serializeRequestObjectWithNullAlgorithm(claims);
						// the OP fetches the request object from the suite (upstream: handleHttp for the request_uri path)
						serveRequestObject(op, uri, requestObjectJwt);
						return requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(op, params, claims, uri);
					},
				}),
			);
			const response = await authz.authorize(op, request);
			await completeCodeFlow(op, client, request, response);
		});

		// https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_request_uri_Sig
		// upstream: openid/OIDCCRequestUriSignedRS256.java (OP-request_uri-Sig)
		test("oidcc-request-uri-signed-rs256: an authorization request passing an RS256 signed request object by reference completes", async ({
			op,
			configureClient,
		}) => {
			let requestUri: requestObject.RequestUri | null = null;
			const client = await configureClient({
				customize: (req) => {
					requestUri = requestObject.createRandomRequestUriWithFragment(op.baseUrl, "OIDCC-6.2");
					registration.addRequestUriToDynamicRegistrationRequest(req, requestUri.fullUrl);
					registration.addRequestObjectSigningAlgRS256ToDynamicRegistrationRequest(req);
				},
			});
			// UPSTREAM: with client_secret_jwt the module keeps the RSA keys for the request object; src/op does not
			// support client_secret_jwt client authentication (yet)
			soft(() => discovery.checkDiscEndpointRequestUriParameterSupported(op.metadata, "OIDCD-3"));
			soft(() =>
				discoveryEndpoint.checkDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256(op.metadata, "OIDCD-3"),
			);
			const uri = suiteRequestUri(requestUri);

			const request = await block("Make request to authorization endpoint", async () => {
				let claims: Record<string, unknown> = {};
				const authorizationRequest = authz.createAuthorizationRequest(op, client.client, {
					buildRedirect: (_, params) => {
						claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(params);
						// aud/iss weren't sent in the python, but are recommended by the spec so we send them
						requestObject.addAudToRequestObject(claims, op.metadata, "OIDCC-6.1");
						requestObject.addIssToRequestObject(claims, client.client, "OIDCC-6.1");
						// UPSTREAM: SignRequestObject runs before the redirect is built; signing is asynchronous here, and
						// the request_uri redirect does not depend on the signed object
						return requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(op, params, claims, uri);
					},
				});
				// the OP fetches the request object from the suite (upstream: handleHttp for the request_uri path)
				serveRequestObject(op, uri, await requestObject.signRequestObject(claims, client));
				return authorizationRequest;
			});
			const response = await authz.authorize(op, request);
			await completeCodeFlow(op, client, request, response);
		});

		// upstream: openid/OIDCCEnsureRequestObjectWithRedirectUri.java
		test(
			"oidcc-ensure-request-object-with-redirect-uri: the redirect_uri in the request object takes precedence over an invalid redirect_uri parameter",
			oidccEnsureRequestObjectWithRedirectUri,
		);

		// upstream: openid/OIDCCRefreshToken.java
		test(
			"oidcc-refresh-token: refresh tokens are issued to and usable by their client only, and refresh the tokens",
			oidccRefreshToken,
		);

		// upstream: openid/OIDCCEnsureClientAssertionWithIssAudSucceeds.java
		test("oidcc-ensure-client-assertion-with-iss-aud-succeeds: a client assertion with the issuer as audience is accepted at the token endpoint, or rejected with invalid_client", async ({
			op,
			client,
		}) => {
			discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client),
			);
			const response = await authz.authorize(op, request);

			await block("Verify authorization endpoint response", async () => {
				authz.checkAuthorizationResponse(op, request, response);
				const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);

				// the client assertion's audience is the issuer, not the token endpoint
				const tokenRequest = token.createTokenEndpointRequestForAuthorizationCodeGrant(code, op.redirectUri);
				await token.addClientAssertionToRequest(op, tokenRequest, client, {
					updateClaims: (claims) => token.updateClientAuthenticationAssertionClaimsWithISSAud(claims, op.metadata),
				});
				const tokenResponse = await token.callTokenEndpoint(op, tokenRequest);

				// If we get an error back from the token endpoint server it must be an 'invalid_client' error (only a warning)
				if (tokenResponse.json?.["error"]) {
					const name = "token_endpoint_response";
					const json = tokenResponse.json;
					soft(() => token.checkIfTokenEndpointResponseError(tokenResponse), "warning");
					soft(() => token.checkTokenEndpointReturnedJsonContentType(tokenResponse, "OIDCC-3.1.3.4"));
					soft(() => token.validateErrorFromTokenEndpointResponseError(tokenResponse, "RFC6749-5.2"));
					soft(
						() =>
							checkErrorDescriptionContainsCRLFTAB(
								"CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB",
								name,
								json,
								"RFC6749-5.2",
							),
						"warning",
					);
					soft(() =>
						validateErrorDescription(
							"ValidateErrorDescriptionFromTokenEndpointResponseError",
							name,
							json,
							"RFC6749-5.2",
						),
					);
					soft(() => validateErrorUri("ValidateErrorUriFromTokenEndpointResponseError", name, json, "RFC6749-5.2"));
					soft(() =>
						token.checkTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError(tokenResponse, "RFC6749-5.2"),
					);
					soft(() => token.checkErrorFromTokenEndpointResponseErrorInvalidClient(tokenResponse, "RFC6749-5.2"));
				} else {
					const tokens = await token.requestAuthorizationCode(op, client, tokenRequest, {
						response: tokenResponse,
						checkStatus: false,
					});
					await idToken.performStandardIdTokenChecks(op, client.client, request, tokens.idToken);
				}
				// stop after checking token endpoint response
			});
		});
	});
});
