/**
 * OpenID Connect Core: Basic Certification Profile, OP tests (upstream openid/OIDCCBasicTestPlan.java).
 *
 * The plan fixes response_type=code, client_auth_type=client_secret_basic and response_mode=default; the user
 * selects server_metadata and client_registration (CONFORMANCE_VARIANT or the CI project).
 *
 *   CONFORMANCE_PROJECT=op-basic-dynamic pnpm test tests/op/basic.spec.ts
 */
import * as authz from "../../src/op/authorization.ts";
import * as discovery from "../../src/op/discovery.ts";
import { ensureContentTypeJson, ensureHttpStatusCodeIs200 } from "../../src/op/endpoint.ts";
import * as idToken from "../../src/op/id-token.ts";
import * as registration from "../../src/op/registration.ts";
import * as token from "../../src/op/token.ts";
import * as userinfo from "../../src/op/userinfo.ts";
import { block, soft } from "../../src/suite/conditions.ts";
import { test } from "../fixtures.ts";

test.describe("oidcc-basic-certification-test-plan", () => {
	test.use({
		plan: {
			name: "oidcc-basic-certification-test-plan",
			variant: { response_type: "code", client_auth_type: "client_secret_basic", response_mode: "default" },
		},
	});

	// upstream: openid/OIDCCServerTest.java (OP-Response-code)
	test("oidcc-server: the code flow returns a valid code, tokens and id_token, and the access token works at userinfo", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			soft(() => authz.ensureMinimumAuthorizationCodeLength(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
			soft(() => authz.ensureMinimumAuthorizationCodeEntropy(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));

			const tokenRequest = await token.createAuthorizationCodeRequest(op, client, code);
			const result = await token.requestAuthorizationCode(op, client, tokenRequest);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			// the python suite did not check this
			soft(() => idToken.ensureIdTokenDoesNotContainName(result.idToken, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
			// RFC6749 recommends expires_in
			soft(() => token.extractExpiresInFromTokenEndpointResponse(result.response, "RFC6749-5.1"), "warning");
			// at_hash and c_hash are optional in the token endpoint's id_token, but must be correct when present
			idToken.checkOptionalHashes(result.idToken, result.accessToken, code);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
			const res = await userinfo.callProtectedResource(url, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		soft(() => idToken.ensureIdTokenDoesNotContainNonRequestedClaims(tokens.idToken, request), "warning");
	});

	// upstream: openid/OIDCCResponseTypeMissing.java (OP-Response-Missing)
	test("oidcc-response-type-missing: a request without response_type is rejected with an error redirect or an error page", async ({
		op,
		client,
	}) => {
		const { request, placeholder } = await block("Make request to authorization endpoint", () => ({
			request: authz.createAuthorizationRequest(op, client.client, {
				omit: { response_type: "Miss out the response_type" },
			}),
			placeholder: authz.expectResponseTypeMissingErrorPage("RFC6749-3.1.1"),
		}));
		// the OP either redirects back with an error, or shows an error page (the browser automation screenshots it)
		const response = await authz.authorizeExpectingErrorPageOrRedirect(op, request, placeholder);
		if (response == null) {
			// the OP showed an error page: the screenshot in the log is for review (result REVIEW), as upstream
			return;
		}

		await block("Verify authorization endpoint response", () => {
			authz.checkCallbackLocation(request, response);
			authz.checkAuthorizationErrorResponse(op, request, response);
			soft(() =>
				authz.checkErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType(
					response,
					"RFC6749-3.1.1",
				),
			);
		});
	});

	test.describe(() => {
		// upstream @VariantNotApplicable: the module registers a client without an id_token signing alg
		test.skip(({ variant }) => variant.client_registration === "static_client", "not applicable to static clients");

		// upstream: openid/OIDCCIdTokenSignature.java (OP-IDToken-Signature, OP-IDToken-kid)
		test("oidcc-idtoken-signature: without a requested algorithm the id_token is signed with RS256 and names its key", async ({
			op,
			client,
		}) => {
			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client),
			);
			const response = await authz.authorize(op, request);

			const tokens = await block("Verify authorization endpoint response", async () => {
				authz.checkAuthorizationResponse(op, request, response);
				const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
				const result = await token.requestAuthorizationCode(
					op,
					client,
					await token.createAuthorizationCodeRequest(op, client, code),
				);
				// OIDCC-10.1 only requires a kid when the OP has several keys; the python suite required it always
				soft(() => idToken.ensureIdTokenContainsKid(result.idToken, "OIDCC-10.1"));
				soft(() => idToken.ensureIdTokenSignatureIsRS256(result.idToken, "OIDCC-3.1.3.7"));
				await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
				return result;
			});

			await block("Userinfo endpoint tests", async () => {
				const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
				const res = await userinfo.callProtectedResource(url, tokens.accessToken);
				soft(() => ensureHttpStatusCodeIs200(res));
			});
		});
	});

	// upstream: openid/OIDCCAuthCodeReuse.java (OP-OAuth-2nd)
	test("oidcc-codereuse: a second token request with the same code is rejected with invalid_grant", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const { tokenRequest, tokens } = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const codeRequest = await token.createAuthorizationCodeRequest(op, client, code);
			const result = await token.requestAuthorizationCode(op, client, codeRequest);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return { tokenRequest: codeRequest, tokens: result };
		});

		await block("Userinfo endpoint tests", async () => {
			const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
			const res = await userinfo.callProtectedResource(url, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		await block("Attempting reuse of authorization code", async () => {
			const second = await token.callTokenEndpoint(op, tokenRequest);
			token.checkAuthorizationCodeReuseResponse(second);
		});
	});

	// The modules below are the plan's response_type=code flows (upstream AbstractOIDCCServerTest): the response types
	// of the other plans (id_token from the authorization endpoint, hybrid) are not part of this plan.

	// upstream: openid/OIDCCScopeAddress.java (OP-scope-address)
	test("oidcc-scope-address: scope=openid address returns the address claim at the userinfo endpoint", async ({
		op,
		client,
	}) => {
		registration.setScopeInClientConfigurationToOpenIdAddress(client.client);
		const notSupported = discovery.scopesNotSupportedReason(op, client.client);
		test.skip(notSupported !== null, notSupported ?? "");
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, tokens.idToken, request);
	});

	// upstream: openid/OIDCCScopeAll.java (OP-scope-all)
	test("oidcc-scope-all: scope=openid email phone address profile returns all the scopes' claims at the userinfo endpoint", async ({
		op,
		client,
	}) => {
		registration.setScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile(client.client);
		const notSupported = discovery.scopesNotSupportedReason(op, client.client);
		test.skip(notSupported !== null, notSupported ?? "");
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, tokens.idToken, request);
	});

	// upstream: openid/OIDCCScopeEmail.java (OP-scope-email)
	test("oidcc-scope-email: scope=openid email returns the email claims at the userinfo endpoint, not in the id_token", async ({
		op,
		client,
	}) => {
		registration.setScopeInClientConfigurationToOpenIdEmail(client.client);
		const notSupported = discovery.scopesNotSupportedReason(op, client.client);
		test.skip(notSupported !== null, notSupported ?? "");
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			// the python test did not check this as far as I know
			soft(() => idToken.ensureIdTokenDoesNotContainName(result.idToken, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
			// we have an access token so the response should not be in the id_token
			soft(() => idToken.ensureIdTokenDoesNotContainEmailForScopeEmail(result.idToken, "OIDCC-5.4"), "warning");
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, tokens.idToken, request);
		soft(() => userinfo.ensureUserInfoDoesNotContainName(info, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
	});

	// upstream: openid/OIDCCScopePhone.java (OP-scope-phone)
	test("oidcc-scope-phone: scope=openid phone returns the phone claims at the userinfo endpoint", async ({
		op,
		client,
	}) => {
		registration.setScopeInClientConfigurationToOpenIdPhone(client.client);
		const notSupported = discovery.scopesNotSupportedReason(op, client.client);
		test.skip(notSupported !== null, notSupported ?? "");
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, tokens.idToken, request);
	});

	// upstream: openid/OIDCCScopeProfile.java (OP-scope-profile)
	test("oidcc-scope-profile: scope=openid profile returns the profile claims at the userinfo endpoint", async ({
		op,
		client,
	}) => {
		registration.setScopeInClientConfigurationToOpenIdProfile(client.client);
		const notSupported = discovery.scopesNotSupportedReason(op, client.client);
		test.skip(notSupported !== null, notSupported ?? "");
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, tokens.idToken, request);
	});

	// upstream: openid/OIDCCClaimsEssential.java (OP-claims-essential)
	test("oidcc-claims-essential: a request for the essential name claim at userinfo succeeds and returns the name", async ({
		op,
		client,
	}) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) =>
					authz.addUserInfoEssentialNameClaimToAuthorizationEndpointRequest(params, "OIDCC-5.5", "OIDCC-5.5.1"),
			}),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, tokens.idToken, request);
		soft(() => userinfo.ensureUserInfoContainsName(info, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
		// the python test did not check this as far as I know
		soft(() => idToken.ensureIdTokenDoesNotContainName(tokens.idToken, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
	});

	// upstream: openid/OIDCCClaimsLocales.java (OP-Req-claims_locales)
	test("oidcc-claims-locales: a request with claims_locales=se does not result in an error", async ({ op, client }) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.addClaimsLocalesSeToAuthorizationEndpointRequest(params, "OIDCC-5.2", "OIDCC-15.1"),
			}),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});
	});

	// upstream: openid/OIDCCUserInfoGet.java (OP-UserInfo-Endpoint)
	test("oidcc-userinfo-get: the userinfo endpoint answers a GET with the access token in the Authorization header", async ({
		op,
		client,
	}) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		soft(() => ensureContentTypeJson(res, "OIDCC-5.3.2"));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateExtractedUserInfoResponse(info);
	});

	// upstream: openid/OIDCCUserInfoPostBody.java (OP-UserInfo-Body)
	test("oidcc-userinfo-post-body: the userinfo endpoint answers a POST with the access token in the body, or warns that it does not support it", async ({
		op,
		client,
	}) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpointWithBearerTokenInBody(op, tokens.accessToken, "OIDCC-5.3.1");
		if (res.status < 200 || res.status >= 300) {
			// support for the access token in the body is optional: a warning, not a failure
			soft(() => userinfo.userInfoEndpointWithAccessTokenInBodyNotSupported(), "warning");
		} else {
			soft(() => ensureContentTypeJson(res, "OIDCC-5.3.2"));
			const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
			userinfo.validateExtractedUserInfoResponse(info);
		}
	});

	// upstream: openid/OIDCCUserInfoPostHeader.java (OP-UserInfo-Header)
	test("oidcc-userinfo-post-header: the userinfo endpoint answers a POST with the access token in the Authorization header", async ({
		op,
		client,
	}) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const method = userinfo.setResourceMethodToPost();
		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, { method }, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		soft(() => ensureContentTypeJson(res, "OIDCC-5.3.2"));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateExtractedUserInfoResponse(info);
	});

	// upstream: openid/OIDCCAlternateHappyFlow.java
	test("oidcc-alternate-happy-flow: reversed scope order and reversed parameter order in the request make no difference", async ({
		op,
		client,
	}) => {
		registration.setScopeInClientConfigurationToOpenIdEmail(client.client);
		const notSupported = discovery.scopesNotSupportedReason(op, client.client);
		test.skip(notSupported !== null, notSupported ?? "");
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.reverseScopeOrderInAuthorizationEndpointRequest(params, "RFC6749-3.3"),
				buildRedirect: authz.buildPlainRedirectToAuthorizationEndpointReorderedParams,
			}),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			// as oidcc-scope-email
			soft(() => idToken.ensureIdTokenDoesNotContainName(result.idToken, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
			soft(() => idToken.ensureIdTokenDoesNotContainEmailForScopeEmail(result.idToken, "OIDCC-5.4"), "warning");
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});

		const res = await userinfo.callUserInfoEndpoint(op, tokens.accessToken, {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, tokens.idToken, request);
		soft(() => userinfo.ensureUserInfoDoesNotContainName(info, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
	});

	// upstream: openid/OIDCCDisplayPage.java (OP-display-page)
	test("oidcc-display-page: a request with display=page does not result in an error", async ({ op, client }) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.addDisplayPageToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
			}),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});
	});

	// upstream: openid/OIDCCDisplayPopup.java (OP-display-popup)
	test("oidcc-display-popup: a request with display=popup does not result in an error", async ({ op, client }) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.addDisplayPopupToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
			}),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});
	});

	// upstream: openid/OIDCCUiLocales.java (OP-Req-ui_locales)
	test("oidcc-ui-locales: a request with ui_locales does not result in an error", async ({ op, client }) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) =>
					authz.addUiLocalesFromConfigurationToAuthorizationEndpointRequest(op, params, "OIDCC-3.1.2.1"),
			}),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});
	});

	// upstream: openid/OIDCCLoginHint.java (OP-Req-login_hint)
	test("oidcc-login-hint: a request with a login_hint does not result in an error", async ({ op, client }) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) =>
					authz.addLoginHintFromConfigurationToAuthorizationEndpointRequest(op, params, "OIDCC-3.1.2.1"),
			}),
		);
		const response = await authz.authorize(op, request);

		const tokens = await block("Verify authorization endpoint response", async () => {
			authz.checkAuthorizationResponse(op, request, response);
			const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
			const result = await token.requestAuthorizationCode(
				op,
				client,
				await token.createAuthorizationCodeRequest(op, client, code),
			);
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
			return result;
		});

		await block("Userinfo endpoint tests", async () => {
			const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
			soft(() => ensureHttpStatusCodeIs200(res));
		});
	});

	// upstream: openid/OIDCCIdTokenHint.java (OP-Req-id_token_hint)
	test("oidcc-id-token-hint: a second authorization with prompt=none and the first id_token as id_token_hint succeeds with the same sub", async ({
		op,
		client,
	}) => {
		const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		// both authorizations run the same flow (upstream AbstractOIDCCSameAuthTwiceServerTest); the blocks of the
		// second one are prefixed, and `steps` are the module's additions to its request
		const authorization = async (prefix: string, steps?: (params: Record<string, unknown>) => void) => {
			const request = await block(prefix + "Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client, { steps }),
			);
			const response = await authz.authorize(op, request);

			const tokens = await block(prefix + "Verify authorization endpoint response", async () => {
				authz.checkAuthorizationResponse(op, request, response);
				const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
				const result = await token.requestAuthorizationCode(
					op,
					client,
					await token.createAuthorizationCodeRequest(op, client, code),
				);
				await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
				return result;
			});

			await block(prefix + "Userinfo endpoint tests", async () => {
				const res = await userinfo.callProtectedResource(resourceUrl, tokens.accessToken);
				soft(() => ensureHttpStatusCodeIs200(res));
			});
			return tokens;
		};

		const first = await authorization("");
		const second = await authorization("Second authorization: ", (params) => {
			authz.addPromptNoneToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1");
			authz.addIdTokenHintFromFirstLoginToAuthorizationEndpointRequest(
				params,
				first.idToken,
				"OIDCC-3.1.2.1",
				"OIDCC-3.1.2.2",
			);
		});

		// equivalent to same-authn, https://github.com/rohe/oidctest/blob/a306ff8ccd02da456192b595cf48ab5dcfd3d15a/src/oidctest/op/check.py#L1117
		soft(() => idToken.checkIdTokenAuthTimeClaimsSameIfPresent(first.idToken, second.idToken, "OIDCC-2"));
		soft(() => idToken.checkIdTokenSubConsistentForSecondAuthorization(first.idToken, second.idToken, "OIDCC-2"));
	});
});
