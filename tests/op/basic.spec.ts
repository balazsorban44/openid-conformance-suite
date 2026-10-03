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
import { ensureHttpStatusCodeIs200 } from "../../src/op/endpoint.ts";
import * as idToken from "../../src/op/id-token.ts";
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

	// upstream: openid/OIDCCIdTokenSignature.java (OP-IDToken-Signature, OP-IDToken-kid)
	test.describe(() => {
		test.skip(
			({ variant }) => variant.client_registration === "static_client",
			"registers a client without an id_token alg",
		);

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
});
