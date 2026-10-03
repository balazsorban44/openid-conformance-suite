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
import { ensureContentTypeJson, ensureHttpStatusCodeIs200, ensureHttpStatusCodeIs4xx } from "../../src/op/endpoint.ts";
import * as idToken from "../../src/op/id-token.ts";
import * as registration from "../../src/op/registration.ts";
import * as requestObject from "../../src/op/request-object.ts";
import * as token from "../../src/op/token.ts";
import * as userinfo from "../../src/op/userinfo.ts";
import { block, soft } from "../../src/suite/conditions.ts";
import { waitFor2Seconds, waitFor30Seconds, waitForOneSecond } from "../../src/suite/wait.ts";
import { skipTest, test } from "../fixtures.ts";
import {
	completeCodeFlow,
	oidccEnsureRequestObjectWithRedirectUri,
	oidccIdTokenUnsigned,
	oidccRefreshToken,
	oidccServer,
	skipIfNoneUnsupported,
} from "./shared.ts";

test.describe("oidcc-basic-certification-test-plan", () => {
	test.use({
		plan: {
			name: "oidcc-basic-certification-test-plan",
			variant: { response_type: "code", client_auth_type: "client_secret_basic", response_mode: "default" },
		},
	});

	// upstream: openid/OIDCCServerTest.java (OP-Response-code)
	test(
		"oidcc-server: the code flow returns a valid code, tokens and id_token, and the access token works at userinfo",
		oidccServer,
	);

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

	// upstream: openid/OIDCCPromptLogin.java (OP-prompt-login)
	test("oidcc-prompt-login: a second request with prompt=login makes the OP ask the user to log in again, with a later auth_time", async ({
		op,
		client,
	}) => {
		const firstRequest = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const firstResponse = await authz.authorize(op, firstRequest);
		const first = await completeCodeFlow(op, client, firstRequest, firstResponse);

		const { request, placeholder } = await block(
			"Second authorization: Make request to authorization endpoint",
			async () => {
				// make sure the auth definitely happens at least 1 second after the original one, so auth_time will be different
				await waitForOneSecond();
				return {
					request: authz.createAuthorizationRequest(op, client.client, {
						steps: (params) =>
							authz.addPromptLoginToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
					}),
					// asking the user for a screenshot of the second login seems a little pointless as there's no way anyone
					// can verify it's from the second login, not the first
					placeholder: authz.expectSecondLoginPage("OIDCC-3.1.2.1"),
				};
			},
		);
		const response = await authz.authorizeWithPlaceholder(op, request, placeholder);
		const second = await completeCodeFlow(op, client, request, response, { prefix: "Second authorization: " });

		soft(() => idToken.checkSecondIdTokenAuthTimeIsLaterIfPresent(first.idToken, second.idToken, "OIDCC-2"));
	});

	// upstream: openid/OIDCCPromptNoneNotLoggedIn.java (OP-prompt-none-NotLoggedIn)
	test("oidcc-prompt-none-not-logged-in: prompt=none without a session is rejected with an error that required a user interface", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				// use a longer state value to check OP doesn't corrupt it in the error response
				stateLength: 128,
				steps: (params) => authz.addPromptNoneToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
			}),
		);
		const response = await authz.authorize(op, request);

		await block("Verify authorization endpoint response", () => {
			authz.checkCallbackLocation(request, response);
			authz.checkAuthorizationErrorResponse(op, request, response);
			soft(() => authz.checkErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface(response, "OIDCC-3.1.2.6"));
		});
	});

	// upstream: openid/OIDCCPromptNoneLoggedIn.java (OP-prompt-none-LoggedIn)
	test("oidcc-prompt-none-logged-in: a second request with prompt=none succeeds without a login, with the same sub and auth_time", async ({
		op,
		client,
	}) => {
		const firstRequest = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const firstResponse = await authz.authorize(op, firstRequest);
		const first = await completeCodeFlow(op, client, firstRequest, firstResponse);

		const request = await block("Second authorization: Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.addPromptNoneToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
			}),
		);
		const response = await authz.authorize(op, request);
		const second = await completeCodeFlow(op, client, request, response, { prefix: "Second authorization: " });

		// these two checks are equivalent to same-authn in the python suite
		soft(() => idToken.checkIdTokenAuthTimeClaimsSameIfPresent(first.idToken, second.idToken, "OIDCC-2"));
		soft(() => idToken.checkIdTokenSubConsistentForSecondAuthorization(first.idToken, second.idToken, "OIDCC-2"));
	});

	// upstream: openid/OIDCCMaxAge1.java (OP-Req-max_age=1)
	test("oidcc-max-age-1: a second request with max_age=1 after 2 seconds makes the OP ask for a login again and return a later auth_time", async ({
		op,
		client,
	}) => {
		const firstRequest = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const firstResponse = await authz.authorize(op, firstRequest);
		const first = await completeCodeFlow(op, client, firstRequest, firstResponse);

		const { request, placeholder } = await block(
			"Second authorization: Make request to authorization endpoint",
			async () => {
				// we're sending max_age=1, so after 1 second the previous authentication is just still valid - so wait for
				// 2 seconds
				await waitFor2Seconds();
				return {
					request: authz.createAuthorizationRequest(op, client.client, {
						steps: (params) => authz.addMaxAge1ToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
					}),
					placeholder: authz.expectSecondLoginPage("OIDCC-3.1.2.1"),
				};
			},
		);
		const response = await authz.authorizeWithPlaceholder(op, request, placeholder);
		await completeCodeFlow(op, client, request, response, {
			prefix: "Second authorization: ",
			performIdTokenValidation: async (second) => {
				await idToken.performStandardIdTokenChecks(op, client.client, request, second);
				soft(() => idToken.checkIdTokenAuthTimeClaimPresentDueToMaxAge(second, "OIDCC-2", "OIDCC-3.1.2.1"));
				soft(() => idToken.checkSecondIdTokenAuthTimeIsLaterIfPresent(first.idToken, second, "OIDCC-2"));
				soft(() => idToken.checkIdTokenAuthTimeIsRecentIfPresent(second, "OIDCC-2"));
			},
		});
	});

	// upstream: openid/OIDCCMaxAge10000.java (OP-Req-max_age=10000)
	test("oidcc-max-age-10000: a second request with max_age=10000 succeeds without a login, with the same sub and auth_time", async ({
		op,
		client,
	}) => {
		// This differs from the python test, where max_age was not included and hence the test could not check that
		// auth_time was consistent as many OPs (correctly) won't return auth_time unless max_age or an essential
		// claim for auth_time is present, so max_age is the only choice to force auth_time to be returned.
		const firstRequest = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.addMaxAge15000ToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
			}),
		);
		const firstResponse = await authz.authorize(op, firstRequest);
		const first = await completeCodeFlow(op, client, firstRequest, firstResponse);
		soft(() =>
			idToken.checkIdTokenAuthTimeClaimPresentDueToMaxAge(first.idToken, "OIDCC-2", "OIDCC-3.1.2.1", "OIDCC-15.1"),
		);

		const request = await block("Second authorization: Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.addMaxAge10000ToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
			}),
		);
		const response = await authz.authorize(op, request);
		const second = await completeCodeFlow(op, client, request, response, { prefix: "Second authorization: " });

		// max_age is requested second time, so auth_time must be present
		soft(() =>
			idToken.checkIdTokenAuthTimeClaimPresentDueToMaxAge(second.idToken, "OIDCC-2", "OIDCC-3.1.2.1", "OIDCC-15.1"),
		);
		soft(() => idToken.checkIdTokenAuthTimeClaimsSameIfPresent(first.idToken, second.idToken, "OIDCC-2"));
		soft(() => idToken.checkIdTokenSubConsistentForSecondAuthorization(first.idToken, second.idToken, "OIDCC-2"));
	});

	// upstream: openid/OIDCCEnsurePostRequestSucceeds.java
	test("oidcc-ensure-post-request-succeeds: an authorization request sent as POST completes with a redirect within 30 seconds", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client),
		);
		const response = await authz.authorizeWithinSeconds(op, request, 30, { method: "POST" });
		if (response == null) {
			// the OP did not call the redirect_uri: a warning, and the test is over
			soft(() => authz.expectRedirectUriHasBeenCalled(response, "OIDCC-3.1.2.1"), "warning");
			return;
		}
		await completeCodeFlow(op, client, request, response);
	});

	// upstream: openid/OIDCCEnsureRegisteredRedirectUri.java (OP-redirect_uri-NotReg)
	test("oidcc-ensure-registered-redirect-uri: a redirect_uri that is not registered shows an error page and never redirects", async ({
		op,
		client,
	}) => {
		// a random redirect URI below the suite's callback, which cannot have been registered
		const { redirectUri, badRedirectPath } = authz.createBadRedirectUriByAppending(op.baseUrl);
		let redirectedToBadUri = false;
		op.server.on("callback/" + badRedirectPath, () => {
			redirectedToBadUri = true;
			return new Response(null, { status: 204 });
		});

		const { request, placeholder } = await block("Make request to authorization endpoint", () => ({
			request: authz.createAuthorizationRequest({ ...op, redirectUri }, client.client),
			placeholder: authz.expectRedirectUriErrorPage("OIDCC-3.1.2.1"),
		}));
		const response = await authz.authorizeExpectingErrorPageOrRedirect(op, request, placeholder);

		if (redirectedToBadUri) {
			throw new Error(
				"The authorization server redirected the user to the requested but randomised/unregistered redirect uri. This must not happen as the provided redirect uri could not have been registered.",
			);
		}
		if (response != null) {
			throw new Error(
				"The authorization server called the registered redirect uri. This should not have happened as the client provided a bad redirect_uri in the request.",
			);
		}
		// the OP showed an error page: the screenshot in the log is for review (result REVIEW), as upstream
	});

	// upstream: openid/OIDCCEnsureRequestWithAcrValuesSucceeds.java (OP-Req-acr_values)
	test("oidcc-ensure-request-with-acr-values-succeeds: a request with acr_values succeeds, and the id_token should carry one of them", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) =>
					authz.oidccAddAcrValuesToAuthorizationEndpointRequest(op, params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
			}),
		);
		const response = await authz.authorize(op, request);
		await completeCodeFlow(op, client, request, response, {
			// just a warning; the minimum required behaviour in the spec is not to fail: "OPs MUST support requests for
			// specific Authentication Context Class Reference values via the acr_values parameter. (Note that the minimum
			// level of support required for this parameter is simply to have its use not result in an error.)"
			performIdTokenValidation: async (tokenIdToken) => {
				await idToken.performStandardIdTokenChecks(op, client.client, request, tokenIdToken);
				soft(
					() =>
						idToken.validateIdTokenACRClaimAgainstAcrValuesRequest(
							tokenIdToken,
							request,
							"OIDCC-3.1.2.1",
							"OIDCC-15.1",
						),
					"warning",
				);
			},
		});
	});

	// upstream: openid/OIDCCEnsureRequestWithUnknownParameterSucceeds.java (OP-Req-NotUnderstood)
	test("oidcc-ensure-request-with-unknown-parameter-succeeds: a request with an unknown parameter succeeds, the parameter ignored", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => authz.addExtraFoobarToAuthorizationEndpointRequest(params, "RFC6749-3.1"),
			}),
		);
		const response = await authz.authorize(op, request);
		await completeCodeFlow(op, client, request, response);
	});

	// upstream: openid/OIDCCEnsureRequestWithValidPkceSucceeds.java
	test("oidcc-ensure-request-with-valid-pkce-succeeds: a request with a valid PKCE challenge succeeds, whether or not the OP supports PKCE", async ({
		op,
		client,
	}) => {
		let codeVerifier = "";
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				steps: (params) => {
					codeVerifier = authz.setupPkceAndAddToAuthorizationRequest(params);
				},
			}),
		);
		const response = await authz.authorize(op, request);
		await completeCodeFlow(op, client, request, response, {
			tokenRequest: (tokenRequest) =>
				token.addCodeVerifierToTokenEndpointRequest(tokenRequest, codeVerifier, "RFC7636-4.5"),
		});
	});

	// upstream: openid/OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow.java (OP-nonce-NoReq-code)
	test("oidcc-ensure-request-without-nonce-succeeds-for-code-flow: a code flow request without nonce returns an authorization code", async ({
		op,
		client,
	}) => {
		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, { omit: { nonce: "NOT adding nonce to request object" } }),
		);
		const response = await authz.authorize(op, request);

		await block("Verify authorization endpoint response", () => {
			authz.checkAuthorizationResponse(op, request, response);
			authz.extractAuthorizationCodeFromAuthorizationResponse(response);
		});
	});

	// upstream: openid/OIDCCAuthCodeReuseAfter30Seconds.java (OP-OAuth-2nd-30s)
	test("oidcc-codereuse-30seconds: a second token request with the same code 30 seconds later is rejected with invalid_grant, and the access token is revoked", async ({
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

		// the real 30 second wait, as upstream
		await waitFor30Seconds();
		await block("Attempting reuse of authorization code", async () => {
			const second = await token.callTokenEndpoint(op, tokenRequest);
			// UPSTREAM: unlike oidcc-codereuse, a 200 response is not accepted with a warning here
			token.checkInvalidGrantErrorResponse(second);
		});

		await block(
			"Testing if access token was revoked after authorization code reuse (the AS 'should' have revoked the access token)",
			async () => {
				const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
				const res = await userinfo.callProtectedResource(url, tokens.accessToken, { requirements: ["RFC6749-4.1.2"] });
				soft(() => ensureHttpStatusCodeIs4xx(res, "RFC6749-4.1.2", "RFC6750-3.1"), "warning");
			},
		);
	});

	test.describe(() => {
		// upstream: the module runs with the client_secret_post variant and, for static clients, the `client_secret_post`
		// client of the configuration
		test.use({
			plan: {
				name: "oidcc-basic-certification-test-plan",
				variant: { response_type: "code", client_auth_type: "client_secret_post", response_mode: "default" },
			},
		});

		// upstream: openid/OIDCCServerTestClientSecretPost.java (OP-ClientAuth-SecretPost-Dynamic)
		test("oidcc-server-client-secret-post: the code flow works with client_secret_post client authentication", async ({
			op,
			configureClient,
		}) => {
			const client = await configureClient({ staticConfigKey: "client_secret_post" });
			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client),
			);
			const response = await authz.authorize(op, request);
			await completeCodeFlow(op, client, request, response);
		});
	});

	test.describe(() => {
		// upstream @VariantNotApplicable: the module registers a client with id_token_signed_response_alg=none
		test.skip(({ variant }) => variant.client_registration === "static_client", "not applicable to static clients");

		// upstream: openid/OIDCCIdTokenUnsigned.java (OP-IDToken-none)
		test(
			"oidcc-idtoken-unsigned: an id_token requested without a signature (alg=none) is returned with alg none",
			oidccIdTokenUnsigned,
		);

		// upstream: openid/OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported.java (OP-request_uri-Unsigned)
		test("oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported: an unsigned request object by request_uri is processed or rejected with request_uri_not_supported", async ({
			op,
			configureClient,
		}) => {
			// the request_uri is registered with the client, so it exists before the registration
			const requestUri = requestObject.createRandomRequestUriWithFragment(op.baseUrl, "OIDCC-6.2");
			const client = await configureClient({
				customize: (registrationRequest) =>
					registration.addRequestUriToDynamicRegistrationRequest(registrationRequest, requestUri.fullUrl),
			});
			// We deliberately skip the hard check for request_uri_parameter_supported here, as we check for a
			// request_uri_not_supported error later.
			skipIfNoneUnsupported(op);

			const request = await block("Make request to authorization endpoint", () =>
				authz.createAuthorizationRequest(op, client.client, {
					buildRedirect: (_, params) => {
						const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(params);
						const requestObjectJwt = requestObject.serializeRequestObjectWithNullAlgorithm(claims);
						// the OP fetches the request object from the suite
						op.server.on(
							requestUri.path,
							() => new Response(requestObjectJwt, { status: 200, headers: { "content-type": "application/jwt" } }),
						);
						return requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(
							op,
							params,
							claims,
							requestUri,
						);
					},
				}),
			);
			const response = await authz.authorize(op, request);

			await completeCodeFlow(op, client, request, response, {
				afterCallbackLocation: () => {
					if (response.params["error"] === "request_uri_not_supported") {
						// we don't check if state is correct here, as state was only passed inside the request object
						// and hence we can't expect the OP to return it
						skipTest(
							"The 'request_uri_not_supported' error from the authorization endpoint indicates that it does not support request_uri (which is permitted behaviour), so request_uri cannot be tested.",
						);
					}
					if (op.variant.server_metadata === "discovery") {
						soft(() => discovery.checkDiscEndpointRequestUriParameterSupported(op.metadata), "warning");
					}
				},
			});
		});
	});

	// upstream: openid/OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported.java (OP-request-Unsigned)
	test("oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported: an unsigned request object by value is processed or rejected with request_not_supported", async ({
		op,
		client,
	}) => {
		skipIfNoneUnsupported(op);

		const request = await block("Make request to authorization endpoint", () =>
			authz.createAuthorizationRequest(op, client.client, {
				buildRedirect: (_, params) => {
					const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(params);
					const requestObjectJwt = requestObject.serializeRequestObjectWithNullAlgorithm(claims);
					return requestObject.buildRequestObjectByValueRedirectToAuthorizationEndpoint(
						op,
						params,
						claims,
						requestObjectJwt,
					);
				},
			}),
		);
		const response = await authz.authorize(op, request);

		await completeCodeFlow(op, client, request, response, {
			afterCallbackLocation: () => {
				if (response.params["error"] === "request_not_supported") {
					// we don't check if state is correct here, as state was only passed inside the request object and hence
					// we can't expect the OP to return it
					skipTest(
						"The 'request_not_supported' error from the authorization endpoint indicates that it does not support request objects (which is permitted behaviour), so request objects cannot be tested.",
					);
				}
				if (op.variant.server_metadata === "discovery") {
					soft(() => discovery.checkDiscEndpointRequestParameterSupported(op.metadata), "warning");
				}
			},
		});
	});

	// upstream: openid/OIDCCEnsureRequestObjectWithRedirectUri.java
	test(
		"oidcc-ensure-request-object-with-redirect-uri: the redirect_uri in the request object takes precedence over the invalid one in the request, or an error page is shown",
		oidccEnsureRequestObjectWithRedirectUri,
	);

	// upstream: openid/OIDCCRefreshToken.java
	test(
		"oidcc-refresh-token: a refresh token gives a new access token (and id_token) and is bound to the client it was issued to",
		oidccRefreshToken,
	);
});
