/**
 * The bodies of the modules several OP plans run (upstream registers the same module class in more than one plan),
 * and the pieces of upstream's AbstractOIDCCServerTest flow the specs share. Each spec registers a shared module
 * under its own title, with its `// upstream:` comment:
 *
 *   // upstream: openid/OIDCCServerTest.java (OP-Response-code)
 *   test("oidcc-server: ...", oidccServer);
 */
import * as authz from "../../src/op/authorization.ts";
import * as discovery from "../../src/op/discovery.ts";
import { performEndpointVerification } from "../../src/op/discovery-endpoint.ts";
import { ensureHttpStatusCodeIs200 } from "../../src/op/endpoint.ts";
import * as idToken from "../../src/op/id-token.ts";
import type { Op, OpVariant } from "../../src/op/op.ts";
import * as refresh from "../../src/op/refresh-token.ts";
import * as registration from "../../src/op/registration.ts";
import type { ClientSetup, RegisteredClient } from "../../src/op/registration.ts";
import * as requestObject from "../../src/op/request-object.ts";
import * as token from "../../src/op/token.ts";
import * as userinfo from "../../src/op/userinfo.ts";
import { block, soft } from "../../src/suite/conditions.ts";
import type { TestConfig } from "../../src/suite/config.ts";
import type { ParsedJwt } from "../../src/suite/jose.ts";
import { skipTest, type ConfigureClient } from "../fixtures.ts";

/** The fixtures the shared test bodies use */
type ClientFixtures = { op: Op; client: RegisteredClient };
type ConfigureClientFixtures = { op: Op; configureClient: ConfigureClient };
type ConformanceFixtures = { conformance: { config: TestConfig }; variant: OpVariant };

export interface CodeFlowOptions {
	/** The prefix of the block names ("Second authorization: "), upstream's currentClientString() */
	prefix?: string;
	/** What the module does between the callback location checks and the rest (onAuthorizationCallbackResponse) */
	afterCallbackLocation?: () => void;
	/** What the module adds to the token request (after the client authentication) */
	tokenRequest?: (tokenRequest: token.TokenRequest) => void;
	/**
	 * The module's performIdTokenValidation, in place of PerformStandardIdTokenChecks (a module that adds checks calls
	 * `idToken.performStandardIdTokenChecks` itself, where upstream calls `super.performIdTokenValidation()`)
	 */
	performIdTokenValidation?: (idToken: ParsedJwt) => void | Promise<void>;
}

/**
 * The code flow after the browser came back, as upstream's AbstractOIDCCServerTest runs it: the checks on the
 * authorization response, the code exchange with the id_token checks, and the userinfo request.
 *
 * upstream: AbstractOIDCCServerTest.processCallback / performPostAuthorizationFlow / requestProtectedResource
 */
export async function completeCodeFlow(
	op: Op,
	client: RegisteredClient,
	request: authz.AuthorizationRequest,
	response: authz.AuthorizationResponse,
	opts: CodeFlowOptions = {},
): Promise<token.Tokens> {
	const prefix = opts.prefix ?? "";
	const tokens = await block(prefix + "Verify authorization endpoint response", async () => {
		authz.checkAuthorizationResponse(op, request, response, { afterCallbackLocation: opts.afterCallbackLocation });
		const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
		const tokenRequest = await token.createAuthorizationCodeRequest(op, client, code);
		opts.tokenRequest?.(tokenRequest);
		const result = await token.requestAuthorizationCode(op, client, tokenRequest);
		if (opts.performIdTokenValidation) {
			await opts.performIdTokenValidation(result.idToken);
		} else {
			await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);
		}
		return result;
	});

	await userinfoEndpointTests(op, tokens.accessToken, prefix);
	return tokens;
}

/** upstream: AbstractOIDCCServerTest.requestProtectedResource (the userinfo endpoint is the protected resource) */
export async function userinfoEndpointTests(op: Op, accessToken: token.AccessToken, prefix = ""): Promise<void> {
	await block(prefix + "Userinfo endpoint tests", async () => {
		const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
		const res = await userinfo.callProtectedResource(url, accessToken);
		soft(() => ensureHttpStatusCodeIs200(res));
	});
}

/** upstream: AbstractOIDCCServerTest.skipTestIfNoneUnsupported (modules that send an unsigned request object) */
export function skipIfNoneUnsupported(op: Op): void {
	const reason = discovery.noneRequestObjectSigningAlgUnsupported(op.metadata);
	if (reason != null) {
		skipTest(reason);
	}
}

/**
 * The discovery document is served as JSON and has the metadata the specifications require.
 *
 * upstream: openid/OIDCCDiscoveryEndpointVerification.java
 */
export async function oidccDiscoveryEndpointVerification({ conformance, variant }: ConformanceFixtures): Promise<void> {
	const { config } = conformance;
	// Includes check-http-response assertion (OIDC test)
	const { metadata, response } = await discovery.getDynamicServerConfiguration(config);
	soft(() => discovery.ensureDiscoveryEndpointResponseStatusCodeIs200(response, "OIDCD-4"));
	soft(() => discovery.checkDiscoveryEndpointReturnedJsonContentType(response, "OIDCD-4"));

	await performEndpointVerification({ metadata, config, variant });
}

/** upstream: openid/OIDCCServerTest.java */
export async function oidccServer({ op, client }: ClientFixtures): Promise<void> {
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

	await userinfoEndpointTests(op, tokens.accessToken);

	soft(() => idToken.ensureIdTokenDoesNotContainNonRequestedClaims(tokens.idToken, request), "warning");
}

/**
 * The OP returns an id_token with alg none when the client registered for it; skipped when the OP's metadata does not
 * list `none`.
 *
 * upstream: openid/OIDCCIdTokenUnsigned.java
 */
export async function oidccIdTokenUnsigned({ op, configureClient }: ConfigureClientFixtures): Promise<void> {
	if (op.variant.server_metadata === "discovery") {
		const supported = soft(() => discovery.oidccCheckIdTokenSigningAlgValuesSupportedAlgNone(op.metadata), "info");
		if (supported === undefined) {
			// skipped before any client is registered
			skipTest(
				"The discovery endpoint 'id_token_signing_alg_values_supported' doesn't support 'none' algorithm; this cannot be tested (which is acceptable for certification, servers are not required to support 'none'",
			);
		}
	}
	const client = await configureClient({
		customize: registration.addIdTokenSigningAlgNoneToDynamicRegistrationRequest,
	});
	const request = await block("Make request to authorization endpoint", () =>
		authz.createAuthorizationRequest(op, client.client),
	);
	const response = await authz.authorize(op, request);
	await completeCodeFlow(op, client, request, response, {
		// the standard id_token checks (which verify the signature) do not apply to an unsigned id_token
		performIdTokenValidation: (unsigned) =>
			soft(() => idToken.checkIdTokenSignatureAlgorithm(unsigned, client.registrationRequest ?? {}, "OIDCC-3.1.3.7")),
	});
}

/**
 * An authorization request with a request object (by value) holding the valid redirect_uri, and an invalid
 * redirect_uri parameter: the OP must use the request object's (OIDCC-6.1) or show an error page.
 *
 * upstream: openid/OIDCCEnsureRequestObjectWithRedirectUri.java
 */
export async function oidccEnsureRequestObjectWithRedirectUri({ op, client }: ClientFixtures): Promise<void> {
	skipIfNoneUnsupported(op);

	const { request, placeholder } = await block("Make request to authorization endpoint", () => {
		const withInvalidRedirectUri = authz.createAuthorizationRequest(op, client.client, {
			buildRedirect: (_, params) => {
				const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(params);
				// the request parameter now has an invalid redirect_uri, the request object keeps the valid one
				authz.addInvalidRedirectUriToAuthorizationRequest(params, op.redirectUri, "OIDCC-6.1");
				const requestObjectJwt = requestObject.serializeRequestObjectWithNullAlgorithm(claims);
				return requestObject.buildRequestObjectByValueRedirectToAuthorizationEndpoint(
					op,
					params,
					claims,
					requestObjectJwt,
				);
			},
		});
		return { request: withInvalidRedirectUri, placeholder: authz.expectRedirectUriErrorPage("RFC6749-3.1.2") };
	});
	const response = await authz.authorizeExpectingErrorPageOrRedirect(op, request, placeholder);
	if (response == null) {
		// the OP showed an error page: the screenshot in the log is for review (result REVIEW), as upstream
		return;
	}

	await completeCodeFlow(op, client, request, response, {
		afterCallbackLocation: () => {
			if (response.params["error"] === "request_not_supported") {
				// this is unexpected as the redirect_uri outside the request object was invalid but we received a
				// redirect to the correct redirect_uri
				authz.ensureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri();
			}
			if (op.variant.server_metadata === "discovery") {
				soft(() => discovery.checkDiscEndpointRequestParameterSupported(op.metadata), "warning");
			}
		},
	});
}

/**
 * The clients of oidcc-refresh-token: registered with the refresh_token grant, asking for offline_access.
 *
 * upstream: OIDCCRefreshToken.createDynamicClientRegistrationRequest / completeClientConfiguration
 */
const refreshTokenClientSetup: ClientSetup = {
	customize: registration.addRefreshTokenGrantTypeToDynamicRegistrationRequest,
	completeClientConfiguration: (op, client) => {
		if (op.variant.server_metadata === "discovery") {
			registration.setScopeInClientConfigurationToOpenId(client);
			registration.setScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess(op.metadata, client);
		} else {
			// no discovery, so no idea if server supports offline_access scope or not - request it anyway, servers
			// 'should' ignore unknown scope values
			registration.setScopeInClientConfigurationToOpenIdOfflineAccess(client);
		}
	},
};

/**
 * Two clients each obtain a refresh token and use it; client 1 then presents client 2's refresh token and must be
 * refused.
 *
 * upstream: openid/OIDCCRefreshToken.java (AbstractOIDCCMultipleClient)
 */
export async function oidccRefreshToken({ op, configureClient }: ConfigureClientFixtures): Promise<void> {
	const client = await configureClient(refreshTokenClientSetup);
	const client2 = await configureClient({ ...refreshTokenClientSetup, configKey: "client2" });
	await refreshTokenFlow(op, client, false);
	const refreshToken = await refreshTokenFlow(op, client2, true);

	// try client 2's refresh_token with client 1
	await block("Attempting to use refresh_token issued to client 2 with client 1", () =>
		refresh.refreshTokenRequestExpectingErrorSteps(op, client, refreshToken, { secondClient: false }),
	);
}

/**
 * One client's pass through the refresh token module: authorize with offline_access (and prompt=consent), exchange
 * the code, check the refresh token, use it, and call userinfo with the refreshed access token. Returns the
 * client's latest refresh token.
 *
 * upstream: OIDCCRefreshToken (AbstractOIDCCMultipleClient.performAuthorizationFlow / performPostAuthorizationFlow)
 */
async function refreshTokenFlow(op: Op, client: RegisteredClient, secondClient: boolean): Promise<string> {
	const prefix = secondClient ? "Second client: " : "";
	const request = await block(prefix + "Make request to authorization endpoint", () =>
		authz.createAuthorizationRequest(op, client.client, {
			nonceLength: secondClient ? 43 : undefined,
			steps: (params) =>
				authz.addPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess(params, "OIDCC-11"),
		}),
	);
	const response = await authz.authorize(op, request);

	const { tokens, refreshToken } = await block(prefix + "Verify authorization endpoint response", async () => {
		authz.checkAuthorizationResponse(op, request, response);
		const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
		const result = await token.requestAuthorizationCode(
			op,
			client,
			await token.createAuthorizationCodeRequest(op, client, code),
		);
		await idToken.performStandardIdTokenChecks(op, client.client, request, result.idToken);

		const issued = soft(() => refresh.extractRefreshTokenFromTokenResponse(result.response), "info");
		if (!issued) {
			soft(() => discovery.ensureServerConfigurationDoesNotSupportRefreshToken(op.metadata, "OIDCD-3"), "warning");
			skipTest("Refresh tokens cannot be tested. No refresh token was issued.");
		}
		if (op.variant.server_metadata === "discovery") {
			soft(() => discovery.ensureServerConfigurationSupportsRefreshToken(op.metadata, "OIDCD-3"), "warning");
		}
		soft(() => refresh.ensureRefreshTokenContainsAllowedCharactersOnly(result.response, "RFC6749-A.17"));
		return { tokens: result, refreshToken: issued };
	});

	const refreshed = await block(prefix + "Refresh Token Request", () =>
		refresh.refreshTokenRequestSteps(op, client, refreshToken, tokens, { secondClient }),
	);

	await userinfoEndpointTests(op, refreshed.accessToken, prefix);
	return refreshed.refreshToken;
}
