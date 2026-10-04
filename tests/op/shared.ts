/**
 * The bodies of the modules several OP plans run (upstream registers the same module class in more than one plan),
 * and the pieces of upstream's AbstractOIDCCServerTest flow the specs share. Each spec registers a shared module
 * under its own title, with its `// upstream:` comment:
 *
 *   // upstream: openid/OIDCCServerTest.java (OP-Response-code)
 *   test("oidcc-server: ...", oidccServer);
 *
 * The flow follows the variant's response_type as upstream's AbstractOIDCCServerTest does: the code from the query
 * (code flow) or the fragment / form post (implicit, hybrid), the id_token and access token of the authorization
 * response, the token endpoint for the response types with a code, and the userinfo endpoint with the access token.
 */
import * as authz from "../../src/op/authorization.ts";
import * as discovery from "../../src/op/discovery.ts";
import { performEndpointVerification } from "../../src/op/discovery-endpoint.ts";
import { ensureContentTypeJson, ensureHttpStatusCodeIs200, ensureHttpStatusCodeIs4xx } from "../../src/op/endpoint.ts";
import * as idToken from "../../src/op/id-token.ts";
import type { Op, OpVariant } from "../../src/op/op.ts";
import * as refresh from "../../src/op/refresh-token.ts";
import * as registration from "../../src/op/registration.ts";
import type { ClientSetup, RegisteredClient } from "../../src/op/registration.ts";
import * as requestObject from "../../src/op/request-object.ts";
import * as token from "../../src/op/token.ts";
import * as userinfo from "../../src/op/userinfo.ts";
import { block, skipped, soft } from "../../src/suite/conditions.ts";
import type { TestConfig } from "../../src/suite/config.ts";
import type { ParsedJwt } from "../../src/suite/jose.ts";
import { waitFor2Seconds, waitFor30Seconds, waitForOneSecond } from "../../src/suite/wait.ts";
import { skipTest, test, type ConfigureClient } from "../fixtures.ts";

/** The fixtures the shared test bodies use */
type ClientFixtures = { op: Op; client: RegisteredClient };
type ConfigureClientFixtures = { op: Op; configureClient: ConfigureClient };
type ConformanceFixtures = { conformance: { config: TestConfig }; variant: OpVariant };

/** upstream ResponseType.includesCode() / includesIdToken() / includesToken() */
export function responseTypeIncludes(op: Pick<Op, "variant">, part: "code" | "id_token" | "token"): boolean {
	return op.variant.response_type.split(" ").includes(part);
}

/** What the authorization endpoint returned, checked (upstream env "code", "access_token", "authorization_endpoint_id_token") */
export interface AuthorizationEndpointResult {
	/** response types with code */
	code: string | null;
	/** response types with token */
	accessToken: token.AccessToken | null;
	/** response types with id_token */
	idToken: ParsedJwt | null;
}

export interface FlowOptions {
	/** The prefix of the block names ("Second authorization: "), upstream's currentClientString() */
	prefix?: string;
	/** What the module does between the callback location checks and the rest (onAuthorizationCallbackResponse) */
	afterCallbackLocation?: () => void;
	/**
	 * The module's performIdTokenValidation, in place of PerformStandardIdTokenChecks, for every id_token of the flow
	 * (a module that adds checks calls `idToken.performStandardIdTokenChecks` itself, where upstream calls
	 * `super.performIdTokenValidation()`)
	 */
	performIdTokenValidation?: (idToken: ParsedJwt) => void | Promise<void>;
	/** The module's performAuthorizationEndpointIdTokenValidation (default: performIdTokenValidation) */
	performAuthorizationEndpointIdTokenValidation?: (
		idToken: ParsedJwt,
		authorization: Omit<AuthorizationEndpointResult, "idToken">,
	) => void | Promise<void>;
	/** The module's performAuthorizationCodeValidation (response types with code) */
	performAuthorizationCodeValidation?: (code: string) => void;
	/** What the module adds to the token request (after the client authentication) */
	tokenRequest?: (tokenRequest: token.TokenRequest) => void;
	/** The module's additionalTokenEndpointResponseValidation (default: performIdTokenValidation of its id_token) */
	additionalTokenEndpointResponseValidation?: (tokens: token.Tokens, code: string) => void | Promise<void>;
	/**
	 * The protected resource url the module set up before the flow (upstream configureProtectedResourceUrl); without
	 * it the userinfo endpoint tests set it up themselves
	 */
	resourceUrl?: string;
}

/** A completed flow: what the authorization endpoint and (response types with code) the token endpoint returned */
export interface Flow extends userinfo.FlowIdTokens {
	code: string | null;
	/** the token request (response types with code), for the modules that send it again */
	tokenRequest: token.TokenRequest | null;
	/** the token endpoint's response (response types with code) */
	tokens: token.Tokens | null;
	/** upstream env "id_token": the token endpoint's for the response types with code, else the authorization endpoint's */
	idToken: ParsedJwt;
	/**
	 * upstream env "access_token": the token endpoint's for the response types with code, else the authorization
	 * endpoint's; null for response_type=id_token
	 */
	accessToken: token.AccessToken | null;
}

/**
 * The access token of a flow; the modules that use it are not applicable to response_type=id_token (upstream
 * @VariantNotApplicable), which returns none.
 */
export function accessTokenOf(flow: Pick<Flow, "accessToken">): token.AccessToken {
	if (flow.accessToken == null) {
		throw new Error("response_type=id_token returns no access token: the module is not applicable to it");
	}
	return flow.accessToken;
}

/**
 * The checks on a successful authorization response and what the response type returns: the code, the access token
 * (used at the userinfo endpoint right away) and the id_token (validated). Runs in the caller's "Verify authorization
 * endpoint response" block.
 *
 * upstream: AbstractOIDCCServerTest.processCallback / onAuthorizationCallbackResponse /
 * handleSuccessfulAuthorizationEndpointResponse (up to performPostAuthorizationFlow)
 */
export async function handleAuthorizationEndpointResponse(
	op: Op,
	client: RegisteredClient,
	request: authz.AuthorizationRequest,
	response: authz.AuthorizationResponse,
	opts: FlowOptions = {},
): Promise<AuthorizationEndpointResult> {
	authz.checkAuthorizationResponse(op, request, response, { afterCallbackLocation: opts.afterCallbackLocation });
	const code = responseTypeIncludes(op, "code")
		? authz.extractAuthorizationCodeFromAuthorizationResponse(response)
		: null;
	const accessToken = responseTypeIncludes(op, "token")
		? authz.extractAccessTokenFromAuthorizationResponse(response)
		: null;
	let authorizationEndpointIdToken: ParsedJwt | null = null;
	if (responseTypeIncludes(op, "id_token")) {
		if (client.keys == null) {
			skipped("ValidateIdTokenFromAuthorizationResponseEncryption", { object: "client_jwks" }, "OIDCC-10.2");
		} else {
			const jwks = client.keys.jwks;
			soft(() => authz.validateIdTokenFromAuthorizationResponseEncryption(response, jwks, "OIDCC-10.2"), "warning");
		}
		authorizationEndpointIdToken = await authz.extractIdTokenFromAuthorizationResponse(response, client);
		if (opts.performAuthorizationEndpointIdTokenValidation) {
			await opts.performAuthorizationEndpointIdTokenValidation(authorizationEndpointIdToken, { code, accessToken });
		} else {
			await performIdTokenValidation(op, client, request, authorizationEndpointIdToken, opts);
		}
	}
	if (code != null) {
		opts.performAuthorizationCodeValidation?.(code);
	}
	if (accessToken != null) {
		// upstream: requestProtectedResource's block ends the "Verify authorization endpoint response" one
		await userinfoEndpointTests(op, accessToken, opts.prefix ?? "", opts.resourceUrl);
	}
	return { code, accessToken, idToken: authorizationEndpointIdToken };
}

/** upstream: AbstractOIDCCServerTest.performIdTokenValidation (PerformStandardIdTokenChecks unless the module overrides it) */
async function performIdTokenValidation(
	op: Op,
	client: RegisteredClient,
	request: authz.AuthorizationRequest,
	parsed: ParsedJwt,
	opts: FlowOptions,
): Promise<void> {
	if (opts.performIdTokenValidation) {
		await opts.performIdTokenValidation(parsed);
	} else {
		await idToken.performStandardIdTokenChecks(op, client.client, request, parsed);
	}
}

/**
 * Exchanges the code of the authorization response and checks the token response and its id_token (for the hybrid
 * response types: the same sub as the authorization endpoint's id_token).
 *
 * upstream: AbstractOIDCCServerTest.createAuthorizationCodeRequest / requestAuthorizationCode
 */
export async function exchangeAuthorizationCode(
	op: Op,
	client: RegisteredClient,
	request: authz.AuthorizationRequest,
	authorization: AuthorizationEndpointResult & { code: string },
	opts: FlowOptions = {},
): Promise<{ tokenRequest: token.TokenRequest; tokens: token.Tokens }> {
	const tokenRequest = await token.createAuthorizationCodeRequest(op, client, authorization.code);
	opts.tokenRequest?.(tokenRequest);
	const tokens = await token.requestAuthorizationCode(op, client, tokenRequest);
	if (opts.additionalTokenEndpointResponseValidation) {
		await opts.additionalTokenEndpointResponseValidation(tokens, authorization.code);
	} else {
		await performIdTokenValidation(op, client, request, tokens.idToken, opts);
	}
	const authorizationEndpointIdToken = authorization.idToken;
	if (authorizationEndpointIdToken != null) {
		soft(() => idToken.verifyIdTokenSubConsistentHybridFlow(authorizationEndpointIdToken, tokens.idToken, "OIDCC-2"));
	}
	return { tokenRequest, tokens };
}

/**
 * The flow after the browser came back, as upstream's AbstractOIDCCServerTest runs it for the variant's response
 * type: the checks on the authorization response and what it returned, the code exchange with the id_token checks
 * (response types with code), and the userinfo requests with the access tokens.
 *
 * upstream: AbstractOIDCCServerTest.processCallback / handleSuccessfulAuthorizationEndpointResponse /
 * performPostAuthorizationFlow / requestProtectedResource
 */
export async function completeAuthorizationFlow(
	op: Op,
	client: RegisteredClient,
	request: authz.AuthorizationRequest,
	response: authz.AuthorizationResponse,
	opts: FlowOptions = {},
): Promise<Flow> {
	const prefix = opts.prefix ?? "";
	const flow = await block(prefix + "Verify authorization endpoint response", async (): Promise<Flow> => {
		const authorization = await handleAuthorizationEndpointResponse(op, client, request, response, opts);
		const { code } = authorization;
		const fromAuthorizationEndpoint = {
			code,
			authorizationEndpointIdToken: authorization.idToken,
			tokenEndpointIdToken: null,
			tokenRequest: null,
			tokens: null,
			accessToken: authorization.accessToken,
		};
		if (code == null) {
			// implicit: the authorization endpoint's id_token is the flow's
			return { ...fromAuthorizationEndpoint, idToken: authorization.idToken as ParsedJwt };
		}
		const { tokenRequest, tokens } = await exchangeAuthorizationCode(
			op,
			client,
			request,
			{ ...authorization, code },
			opts,
		);
		return {
			...fromAuthorizationEndpoint,
			tokenEndpointIdToken: tokens.idToken,
			tokenRequest,
			tokens,
			idToken: tokens.idToken,
			accessToken: tokens.accessToken,
		};
	});

	if (flow.tokens != null) {
		await userinfoEndpointTests(op, flow.tokens.accessToken, prefix, opts.resourceUrl);
	}
	return flow;
}

/**
 * upstream: AbstractOIDCCServerTest.requestProtectedResource (the userinfo endpoint is the protected resource, set
 * up here unless the module did before the flow)
 */
export async function userinfoEndpointTests(
	op: Op,
	accessToken: token.AccessToken,
	prefix = "",
	resourceUrl?: string,
): Promise<void> {
	await block(prefix + "Userinfo endpoint tests", async () => {
		const url = resourceUrl ?? discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
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

/** The authorization request of a module with `steps` added (upstream createAuthorizationRequestSequence().then(...)) */
function makeRequest(
	op: Op,
	client: RegisteredClient,
	opts: authz.AuthorizationRequestOptions = {},
	prefix = "",
): Promise<authz.AuthorizationRequest> {
	return block(prefix + "Make request to authorization endpoint", () =>
		authz.createAuthorizationRequest(op, client.client, opts),
	);
}

/** upstream: openid/OIDCCServerTest.java */
export async function oidccServer({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client);
	const response = await authz.authorize(op, request);

	const idTokenChecks = async (parsed: ParsedJwt) => {
		await idToken.performStandardIdTokenChecks(op, client.client, request, parsed);
		// the python suite did not check this
		soft(() => idToken.ensureIdTokenDoesNotContainName(parsed, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
	};
	const flow = await completeAuthorizationFlow(op, client, request, response, {
		performIdTokenValidation: idTokenChecks,
		performAuthorizationEndpointIdTokenValidation: async (parsed, { accessToken, code }) => {
			await idTokenChecks(parsed);
			// OP-IDToken-at_hash, OP-IDToken-c_hash
			idToken.checkAuthorizationEndpointHashes(parsed, op.variant.response_type, accessToken, code);
		},
		performAuthorizationCodeValidation: (code) => {
			soft(() => authz.ensureMinimumAuthorizationCodeLength(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
			soft(() => authz.ensureMinimumAuthorizationCodeEntropy(code, "RFC6749-10.10", "RFC6819-5.1.4.2-2"));
		},
		additionalTokenEndpointResponseValidation: async (tokens, code) => {
			await idTokenChecks(tokens.idToken);
			// RFC6749 recommends expires_in
			soft(() => token.extractExpiresInFromTokenEndpointResponse(tokens.response, "RFC6749-5.1"), "warning");
			// at_hash and c_hash are optional in the token endpoint's id_token, but must be correct when present
			idToken.checkOptionalHashes(tokens.idToken, tokens.accessToken, code);
		},
	});

	soft(() => idToken.ensureIdTokenDoesNotContainNonRequestedClaims(flow.idToken, request), "warning");
}

/** upstream: openid/OIDCCResponseTypeMissing.java */
export async function oidccResponseTypeMissing({ op, client }: ClientFixtures): Promise<void> {
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
		// the response is in the query (no response_type was sent) or the form post
		authz.checkCallbackLocation(request, response);
		authz.checkAuthorizationErrorResponse(op, request, response);
		soft(() =>
			authz.checkErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType(response, "RFC6749-3.1.1"),
		);
	});
}

/** upstream: openid/OIDCCIdTokenSignature.java */
export async function oidccIdTokenSignature({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client);
	const response = await authz.authorize(op, request);
	await completeAuthorizationFlow(op, client, request, response, {
		performIdTokenValidation: async (parsed) => {
			// OIDCC-10.1 only requires a kid when the OP has several keys; the python suite required it always
			soft(() => idToken.ensureIdTokenContainsKid(parsed, "OIDCC-10.1"));
			soft(() => idToken.ensureIdTokenSignatureIsRS256(parsed, "OIDCC-3.1.3.7"));
			await idToken.performStandardIdTokenChecks(op, client.client, request, parsed);
		},
	});
}

/** upstream: openid/OIDCCAuthCodeReuse.java (AbstractOIDCCAuthCodeReuse) */
export async function oidccCodeReuse({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client);
	const response = await authz.authorize(op, request);
	const flow = await completeAuthorizationFlow(op, client, request, response);

	await block("Attempting reuse of authorization code", async () => {
		const second = await token.callTokenEndpoint(op, flow.tokenRequest as token.TokenRequest);
		token.checkAuthorizationCodeReuseResponse(second);
	});
}

/** upstream: openid/OIDCCAuthCodeReuseAfter30Seconds.java (AbstractOIDCCAuthCodeReuse) */
export async function oidccCodeReuse30Seconds({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client);
	const response = await authz.authorize(op, request);
	const flow = await completeAuthorizationFlow(op, client, request, response);

	// upstream's 30 second wait; `server.code_reuse_delay` shortens it for an OP that rejects a reused code at once
	await waitFor30Seconds(op.config);
	await block("Attempting reuse of authorization code", async () => {
		const second = await token.callTokenEndpoint(op, flow.tokenRequest as token.TokenRequest);
		// UPSTREAM: unlike oidcc-codereuse, a 200 response is not accepted with a warning here
		token.checkInvalidGrantErrorResponse(second);
	});

	await block(
		"Testing if access token was revoked after authorization code reuse (the AS 'should' have revoked the access token)",
		async () => {
			const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
			const res = await userinfo.callProtectedResource(url, accessTokenOf(flow), {
				requirements: ["RFC6749-4.1.2"],
			});
			soft(() => ensureHttpStatusCodeIs4xx(res, "RFC6749-4.1.2", "RFC6750-3.1"), "warning");
		},
	);
}

/** What a module adds to AbstractOIDCCReturnedClaimsServerTest's checks after the flow */
interface ReturnedClaimsOptions {
	/** the module's validateUserInfoResponse additions (response types with an access token) */
	validateUserInfoResponse?: (info: userinfo.UserInfo) => void;
	/** the module's validateIdTokenForResponseTypeIdToken additions (response_type=id_token) */
	validateIdTokenForResponseTypeIdToken?: (authorizationEndpointIdToken: ParsedJwt) => void;
}

/**
 * The claims the module requested are returned: from the userinfo endpoint when the flow has an access token,
 * otherwise in the authorization endpoint's id_token.
 *
 * upstream: AbstractOIDCCReturnedClaimsServerTest.onPostAuthorizationFlowComplete
 */
async function verifyReturnedClaims(
	op: Op,
	request: authz.AuthorizationRequest,
	flow: Flow,
	opts: ReturnedClaimsOptions = {},
): Promise<void> {
	// Verify scopes returned in userinfo endpoint if we have access token and otherwise in returned id_token from
	// authorization endpoint
	if (responseTypeIncludes(op, "code") || responseTypeIncludes(op, "token")) {
		const res = await userinfo.callUserInfoEndpoint(op, accessTokenOf(flow), {}, "OIDCC-5.3.1");
		soft(() => ensureHttpStatusCodeIs200(res));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateReturnedClaimsUserInfoResponse(info, flow, request);
		opts.validateUserInfoResponse?.(info);
	} else {
		const authorizationEndpointIdToken = flow.authorizationEndpointIdToken as ParsedJwt;
		soft(
			() =>
				idToken.verifyScopesReturnedInAuthorizationEndpointIdToken(authorizationEndpointIdToken, request, "OIDCC-5.4"),
			"warning",
		);
		opts.validateIdTokenForResponseTypeIdToken?.(authorizationEndpointIdToken);
	}
}

/**
 * A module of AbstractOIDCCReturnedClaimsServerTest that requests the scopes `setScope` sets: skipped when the
 * discovery document says they are not supported, otherwise the flow and the claims of the scopes.
 */
async function returnedClaimsScopeModule(
	op: Op,
	client: RegisteredClient,
	setScope: (client: registration.Client) => void,
	opts: {
		request?: authz.AuthorizationRequestOptions;
		performIdTokenValidation?: (request: authz.AuthorizationRequest) => (parsed: ParsedJwt) => Promise<void>;
	} & ReturnedClaimsOptions = {},
): Promise<void> {
	// upstream: skipTestIfScopesNotSupported
	setScope(client.client);
	const notSupported = discovery.scopesNotSupportedReason(op, client.client);
	test.skip(notSupported !== null, notSupported ?? "");
	const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

	const request = await makeRequest(op, client, opts.request);
	const response = await authz.authorize(op, request);
	const flow = await completeAuthorizationFlow(op, client, request, response, {
		resourceUrl,
		performIdTokenValidation: opts.performIdTokenValidation?.(request),
	});
	await verifyReturnedClaims(op, request, flow, opts);
}

/** upstream: openid/OIDCCScopeAddress.java (AbstractOIDCCReturnedClaimsServerTest) */
export async function oidccScopeAddress({ op, client }: ClientFixtures): Promise<void> {
	await returnedClaimsScopeModule(op, client, registration.setScopeInClientConfigurationToOpenIdAddress);
}

/** upstream: openid/OIDCCScopeAll.java (AbstractOIDCCReturnedClaimsServerTest) */
export async function oidccScopeAll({ op, client }: ClientFixtures): Promise<void> {
	await returnedClaimsScopeModule(
		op,
		client,
		registration.setScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile,
	);
}

/** upstream: openid/OIDCCScopePhone.java (AbstractOIDCCReturnedClaimsServerTest) */
export async function oidccScopePhone({ op, client }: ClientFixtures): Promise<void> {
	await returnedClaimsScopeModule(op, client, registration.setScopeInClientConfigurationToOpenIdPhone);
}

/** upstream: openid/OIDCCScopeProfile.java (AbstractOIDCCReturnedClaimsServerTest) */
export async function oidccScopeProfile({ op, client }: ClientFixtures): Promise<void> {
	await returnedClaimsScopeModule(op, client, registration.setScopeInClientConfigurationToOpenIdProfile);
}

/**
 * OIDCCScopeEmail's checks, which oidcc-alternate-happy-flow inherits.
 *
 * upstream: OIDCCScopeEmail.performIdTokenValidation / validateUserInfoResponse
 */
function scopeEmailChecks(op: Op, client: RegisteredClient) {
	return {
		performIdTokenValidation: (request: authz.AuthorizationRequest) => async (parsed: ParsedJwt) => {
			await idToken.performStandardIdTokenChecks(op, client.client, request, parsed);
			// the python test did not check this as far as I know
			soft(() => idToken.ensureIdTokenDoesNotContainName(parsed, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
			if (responseTypeIncludes(op, "code") || responseTypeIncludes(op, "token")) {
				// we have an access token so the response should not be in the id_token
				soft(() => idToken.ensureIdTokenDoesNotContainEmailForScopeEmail(parsed, "OIDCC-5.4"), "warning");
			}
		},
		validateUserInfoResponse: (info: userinfo.UserInfo) => {
			soft(() => userinfo.ensureUserInfoDoesNotContainName(info, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
		},
	};
}

/** upstream: openid/OIDCCScopeEmail.java (AbstractOIDCCReturnedClaimsServerTest) */
export async function oidccScopeEmail({ op, client }: ClientFixtures): Promise<void> {
	await returnedClaimsScopeModule(
		op,
		client,
		registration.setScopeInClientConfigurationToOpenIdEmail,
		scopeEmailChecks(op, client),
	);
}

/** upstream: openid/OIDCCAlternateHappyFlow.java (OIDCCScopeEmail) */
export async function oidccAlternateHappyFlow({ op, client }: ClientFixtures): Promise<void> {
	await returnedClaimsScopeModule(op, client, registration.setScopeInClientConfigurationToOpenIdEmail, {
		...scopeEmailChecks(op, client),
		request: {
			steps: (params) => authz.reverseScopeOrderInAuthorizationEndpointRequest(params, "RFC6749-3.3"),
			buildRedirect: authz.buildPlainRedirectToAuthorizationEndpointReorderedParams,
		},
	});
}

/** upstream: openid/OIDCCClaimsEssential.java (AbstractOIDCCReturnedClaimsServerTest) */
export async function oidccClaimsEssential({ op, client }: ClientFixtures): Promise<void> {
	const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

	const request = await makeRequest(op, client, {
		// response_type=id_token has no access token for the userinfo endpoint: the claim is requested in the id_token
		steps: (params) =>
			op.variant.response_type === "id_token"
				? authz.addIdTokenEssentialNameClaimToAuthorizationEndpointRequest(params, "OIDCC-5.5", "OIDCC-5.5.1")
				: authz.addUserInfoEssentialNameClaimToAuthorizationEndpointRequest(params, "OIDCC-5.5", "OIDCC-5.5.1"),
	});
	const response = await authz.authorize(op, request);
	const flow = await completeAuthorizationFlow(op, client, request, response, { resourceUrl });

	await verifyReturnedClaims(op, request, flow, {
		validateUserInfoResponse: (info) => {
			soft(() => userinfo.ensureUserInfoContainsName(info, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
			// the python test did not check this as far as I know
			soft(() => idToken.ensureIdTokenDoesNotContainName(flow.idToken, "OIDCC-5.5", "OIDCC-5.5.1"), "warning");
		},
		validateIdTokenForResponseTypeIdToken: (authorizationEndpointIdToken) => {
			soft(
				() => idToken.ensureIdTokenContainsName(authorizationEndpointIdToken, "OIDCC-5.5", "OIDCC-5.5.1"),
				"warning",
			);
		},
	});
}

/**
 * A module that adds `steps` to the request and runs the standard flow: the parameter must not result in an error.
 * upstream: AbstractOIDCCServerTest (createAuthorizationRequestSequence().then(...))
 */
async function flowWithRequestSteps(
	op: Op,
	client: RegisteredClient,
	steps: (params: Record<string, unknown>) => void,
): Promise<void> {
	const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
	const request = await makeRequest(op, client, { steps });
	const response = await authz.authorize(op, request);
	await completeAuthorizationFlow(op, client, request, response, { resourceUrl });
}

/** upstream: openid/OIDCCClaimsLocales.java */
export async function oidccClaimsLocales({ op, client }: ClientFixtures): Promise<void> {
	await flowWithRequestSteps(op, client, (params) =>
		authz.addClaimsLocalesSeToAuthorizationEndpointRequest(params, "OIDCC-5.2", "OIDCC-15.1"),
	);
}

/** upstream: openid/OIDCCDisplayPage.java */
export async function oidccDisplayPage({ op, client }: ClientFixtures): Promise<void> {
	await flowWithRequestSteps(op, client, (params) =>
		authz.addDisplayPageToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
	);
}

/** upstream: openid/OIDCCDisplayPopup.java */
export async function oidccDisplayPopup({ op, client }: ClientFixtures): Promise<void> {
	await flowWithRequestSteps(op, client, (params) =>
		authz.addDisplayPopupToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
	);
}

/** upstream: openid/OIDCCUiLocales.java */
export async function oidccUiLocales({ op, client }: ClientFixtures): Promise<void> {
	await flowWithRequestSteps(op, client, (params) =>
		authz.addUiLocalesFromConfigurationToAuthorizationEndpointRequest(op, params, "OIDCC-3.1.2.1"),
	);
}

/** upstream: openid/OIDCCLoginHint.java */
export async function oidccLoginHint({ op, client }: ClientFixtures): Promise<void> {
	await flowWithRequestSteps(op, client, (params) =>
		authz.addLoginHintFromConfigurationToAuthorizationEndpointRequest(op, params, "OIDCC-3.1.2.1"),
	);
}

/**
 * The flow of the userinfo modules up to their own userinfo request.
 *
 * upstream: AbstractOIDCCUserInfoTest (AbstractOIDCCServerTest up to onPostAuthorizationFlowComplete)
 */
async function userInfoModuleFlow(op: Op, client: RegisteredClient): Promise<Flow> {
	const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
	const request = await makeRequest(op, client);
	const response = await authz.authorize(op, request);
	return completeAuthorizationFlow(op, client, request, response, { resourceUrl });
}

/** upstream: openid/OIDCCUserInfoGet.java (AbstractOIDCCUserInfoTest) */
export async function oidccUserInfoGet({ op, client }: ClientFixtures): Promise<void> {
	const flow = await userInfoModuleFlow(op, client);

	const res = await userinfo.callUserInfoEndpoint(op, accessTokenOf(flow), {}, "OIDCC-5.3.1");
	soft(() => ensureHttpStatusCodeIs200(res));
	soft(() => ensureContentTypeJson(res, "OIDCC-5.3.2"));
	const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
	userinfo.validateExtractedUserInfoResponse(info, flow);
}

/** upstream: openid/OIDCCUserInfoPostBody.java (AbstractOIDCCUserInfoTest) */
export async function oidccUserInfoPostBody({ op, client }: ClientFixtures): Promise<void> {
	const flow = await userInfoModuleFlow(op, client);

	const res = await userinfo.callUserInfoEndpointWithBearerTokenInBody(op, accessTokenOf(flow), "OIDCC-5.3.1");
	if (res.status < 200 || res.status >= 300) {
		// support for the access token in the body is optional: a warning, not a failure
		soft(() => userinfo.userInfoEndpointWithAccessTokenInBodyNotSupported(), "warning");
	} else {
		soft(() => ensureContentTypeJson(res, "OIDCC-5.3.2"));
		const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
		userinfo.validateExtractedUserInfoResponse(info, flow);
	}
}

/** upstream: openid/OIDCCUserInfoPostHeader.java (AbstractOIDCCUserInfoTest) */
export async function oidccUserInfoPostHeader({ op, client }: ClientFixtures): Promise<void> {
	const flow = await userInfoModuleFlow(op, client);

	const method = userinfo.setResourceMethodToPost();
	const res = await userinfo.callUserInfoEndpoint(op, accessTokenOf(flow), { method }, "OIDCC-5.3.1");
	soft(() => ensureHttpStatusCodeIs200(res));
	soft(() => ensureContentTypeJson(res, "OIDCC-5.3.2"));
	const info = userinfo.extractUserInfoFromUserInfoEndpointResponse(res);
	userinfo.validateExtractedUserInfoResponse(info, flow);
}

/** upstream: openid/OIDCCIdTokenHint.java (AbstractOIDCCSameAuthTwiceServerTest) */
export async function oidccIdTokenHint({ op, client }: ClientFixtures): Promise<void> {
	const resourceUrl = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

	const firstRequest = await makeRequest(op, client);
	const firstResponse = await authz.authorize(op, firstRequest);
	// the id_token of the first authentication, for later comparison (from the authorization or the token endpoint)
	const first = await completeAuthorizationFlow(op, client, firstRequest, firstResponse, { resourceUrl });

	const prefix = "Second authorization: ";
	const request = await makeRequest(
		op,
		client,
		{
			steps: (params) => {
				authz.addPromptNoneToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1");
				authz.addIdTokenHintFromFirstLoginToAuthorizationEndpointRequest(
					params,
					first.idToken,
					"OIDCC-3.1.2.1",
					"OIDCC-3.1.2.2",
				);
			},
		},
		prefix,
	);
	const response = await authz.authorize(op, request);
	const second = await completeAuthorizationFlow(op, client, request, response, { prefix, resourceUrl });

	// equivalent to same-authn, https://github.com/rohe/oidctest/blob/a306ff8ccd02da456192b595cf48ab5dcfd3d15a/src/oidctest/op/check.py#L1117
	soft(() => idToken.checkIdTokenAuthTimeClaimsSameIfPresent(first.idToken, second.idToken, "OIDCC-2"));
	soft(() => idToken.checkIdTokenSubConsistentForSecondAuthorization(first.idToken, second.idToken, "OIDCC-2"));
}

/** upstream: openid/OIDCCPromptLogin.java */
export async function oidccPromptLogin({ op, client }: ClientFixtures): Promise<void> {
	const firstRequest = await makeRequest(op, client);
	const firstResponse = await authz.authorize(op, firstRequest);
	const first = await completeAuthorizationFlow(op, client, firstRequest, firstResponse);

	const { request, placeholder } = await block(
		"Second authorization: Make request to authorization endpoint",
		async () => {
			// make sure the auth definitely happens at least 1 second after the original one, so auth_time will be different
			await waitForOneSecond();
			return {
				request: authz.createAuthorizationRequest(op, client.client, {
					steps: (params) => authz.addPromptLoginToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
				}),
				// asking the user for a screenshot of the second login seems a little pointless as there's no way anyone
				// can verify it's from the second login, not the first
				placeholder: authz.expectSecondLoginPage("OIDCC-3.1.2.1"),
			};
		},
	);
	const response = await authz.authorizeWithPlaceholder(op, request, placeholder);
	const second = await completeAuthorizationFlow(op, client, request, response, { prefix: "Second authorization: " });

	soft(() => idToken.checkSecondIdTokenAuthTimeIsLaterIfPresent(first.idToken, second.idToken, "OIDCC-2"));
}

/** upstream: openid/OIDCCPromptNoneNotLoggedIn.java */
export async function oidccPromptNoneNotLoggedIn({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client, {
		// use a longer state value to check OP doesn't corrupt it in the error response
		stateLength: 128,
		steps: (params) => authz.addPromptNoneToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
	});
	const response = await authz.authorize(op, request);

	await block("Verify authorization endpoint response", () => {
		authz.checkCallbackLocation(request, response);
		authz.checkAuthorizationErrorResponse(op, request, response);
		soft(() => authz.checkErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface(response, "OIDCC-3.1.2.6"));
	});
}

/** upstream: openid/OIDCCPromptNoneLoggedIn.java (AbstractOIDCCSameAuthTwiceServerTest) */
export async function oidccPromptNoneLoggedIn({ op, client }: ClientFixtures): Promise<void> {
	const firstRequest = await makeRequest(op, client);
	const firstResponse = await authz.authorize(op, firstRequest);
	const first = await completeAuthorizationFlow(op, client, firstRequest, firstResponse);

	const prefix = "Second authorization: ";
	const request = await makeRequest(
		op,
		client,
		{ steps: (params) => authz.addPromptNoneToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1") },
		prefix,
	);
	const response = await authz.authorize(op, request);
	const second = await completeAuthorizationFlow(op, client, request, response, { prefix });

	// these two checks are equivalent to same-authn in the python suite
	soft(() => idToken.checkIdTokenAuthTimeClaimsSameIfPresent(first.idToken, second.idToken, "OIDCC-2"));
	soft(() => idToken.checkIdTokenSubConsistentForSecondAuthorization(first.idToken, second.idToken, "OIDCC-2"));
}

/** upstream: openid/OIDCCMaxAge1.java */
export async function oidccMaxAge1({ op, client }: ClientFixtures): Promise<void> {
	const firstRequest = await makeRequest(op, client);
	const firstResponse = await authz.authorize(op, firstRequest);
	const first = await completeAuthorizationFlow(op, client, firstRequest, firstResponse);

	const { request, placeholder } = await block(
		"Second authorization: Make request to authorization endpoint",
		async () => {
			// we're sending max_age=1, so after 1 second the previous authentication is just still valid - so wait for 2
			// seconds
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
	await completeAuthorizationFlow(op, client, request, response, {
		prefix: "Second authorization: ",
		performIdTokenValidation: async (second) => {
			await idToken.performStandardIdTokenChecks(op, client.client, request, second);
			soft(() => idToken.checkIdTokenAuthTimeClaimPresentDueToMaxAge(second, "OIDCC-2", "OIDCC-3.1.2.1"));
			soft(() => idToken.checkSecondIdTokenAuthTimeIsLaterIfPresent(first.idToken, second, "OIDCC-2"));
			soft(() => idToken.checkIdTokenAuthTimeIsRecentIfPresent(second, "OIDCC-2"));
		},
	});
}

/** upstream: openid/OIDCCMaxAge10000.java (AbstractOIDCCSameAuthTwiceServerTest) */
export async function oidccMaxAge10000({ op, client }: ClientFixtures): Promise<void> {
	// This differs from the python test, where max_age was not included and hence the test could not check that
	// auth_time was consistent as many OPs (correctly) won't return auth_time unless max_age or an essential claim for
	// auth_time is present, so max_age is the only choice to force auth_time to be returned.
	const firstRequest = await makeRequest(op, client, {
		steps: (params) => authz.addMaxAge15000ToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
	});
	const firstResponse = await authz.authorize(op, firstRequest);
	const first = await completeAuthorizationFlow(op, client, firstRequest, firstResponse);
	soft(() =>
		idToken.checkIdTokenAuthTimeClaimPresentDueToMaxAge(first.idToken, "OIDCC-2", "OIDCC-3.1.2.1", "OIDCC-15.1"),
	);

	const prefix = "Second authorization: ";
	const request = await makeRequest(
		op,
		client,
		{ steps: (params) => authz.addMaxAge10000ToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1") },
		prefix,
	);
	const response = await authz.authorize(op, request);
	const second = await completeAuthorizationFlow(op, client, request, response, { prefix });

	// max_age is requested second time, so auth_time must be present
	soft(() =>
		idToken.checkIdTokenAuthTimeClaimPresentDueToMaxAge(second.idToken, "OIDCC-2", "OIDCC-3.1.2.1", "OIDCC-15.1"),
	);
	soft(() => idToken.checkIdTokenAuthTimeClaimsSameIfPresent(first.idToken, second.idToken, "OIDCC-2"));
	soft(() => idToken.checkIdTokenSubConsistentForSecondAuthorization(first.idToken, second.idToken, "OIDCC-2"));
}

/** upstream: openid/OIDCCEnsurePostRequestSucceeds.java */
export async function oidccEnsurePostRequestSucceeds({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client);
	const response = await authz.authorizeWithinSeconds(op, request, 30, { method: "POST" });
	if (response == null) {
		// the OP did not call the redirect_uri: a warning, and the test is over
		soft(() => authz.expectRedirectUriHasBeenCalled(response, "OIDCC-3.1.2.1"), "warning");
		return;
	}
	await completeAuthorizationFlow(op, client, request, response);
}

/** upstream: openid/OIDCCEnsureRegisteredRedirectUri.java */
export async function oidccEnsureRegisteredRedirectUri({ op, client }: ClientFixtures): Promise<void> {
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
}

/** upstream: openid/OIDCCEnsureRequestWithAcrValuesSucceeds.java */
export async function oidccEnsureRequestWithAcrValuesSucceeds({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client, {
		steps: (params) => authz.oidccAddAcrValuesToAuthorizationEndpointRequest(op, params, "OIDCC-3.1.2.1", "OIDCC-15.1"),
	});
	const response = await authz.authorize(op, request);
	await completeAuthorizationFlow(op, client, request, response, {
		// just a warning; the minimum required behaviour in the spec is not to fail: "OPs MUST support requests for
		// specific Authentication Context Class Reference values via the acr_values parameter. (Note that the minimum
		// level of support required for this parameter is simply to have its use not result in an error.)"
		performIdTokenValidation: async (parsed) => {
			await idToken.performStandardIdTokenChecks(op, client.client, request, parsed);
			soft(
				() => idToken.validateIdTokenACRClaimAgainstAcrValuesRequest(parsed, request, "OIDCC-3.1.2.1", "OIDCC-15.1"),
				"warning",
			);
		},
	});
}

/** upstream: openid/OIDCCEnsureRequestWithUnknownParameterSucceeds.java */
export async function oidccEnsureRequestWithUnknownParameterSucceeds({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client, {
		steps: (params) => authz.addExtraFoobarToAuthorizationEndpointRequest(params, "RFC6749-3.1"),
	});
	const response = await authz.authorize(op, request);
	await completeAuthorizationFlow(op, client, request, response);
}

/** upstream: openid/OIDCCEnsureRequestWithValidPkceSucceeds.java */
export async function oidccEnsureRequestWithValidPkceSucceeds({ op, client }: ClientFixtures): Promise<void> {
	let codeVerifier = "";
	const request = await makeRequest(op, client, {
		steps: (params) => {
			codeVerifier = authz.setupPkceAndAddToAuthorizationRequest(params);
		},
	});
	const response = await authz.authorize(op, request);
	await completeAuthorizationFlow(op, client, request, response, {
		tokenRequest: (tokenRequest) =>
			token.addCodeVerifierToTokenEndpointRequest(tokenRequest, codeVerifier, "RFC7636-4.5"),
	});
}

/**
 * A request without nonce must succeed for the response types without an id_token from the authorization endpoint;
 * the module ends after the authorization response (and, for code token, the userinfo request with its access
 * token).
 *
 * upstream: openid/OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow.java
 */
export async function oidccEnsureRequestWithoutNonceSucceedsForCodeFlow({ op, client }: ClientFixtures): Promise<void> {
	const request = await makeRequest(op, client, { omit: { nonce: "NOT adding nonce to request object" } });
	const response = await authz.authorize(op, request);

	// performPostAuthorizationFlow is overridden: no token request
	await block("Verify authorization endpoint response", () =>
		handleAuthorizationEndpointResponse(op, client, request, response),
	);
}

/**
 * A request without nonce must be rejected for the response types that return an id_token from the authorization
 * endpoint: an invalid_request error redirect, or an error page.
 *
 * upstream: openid/OIDCCEnsureRequestWithoutNonceFails.java
 */
export async function oidccEnsureRequestWithoutNonceFails({ op, client }: ClientFixtures): Promise<void> {
	const { request, placeholder } = await block("Make request to authorization endpoint", () => ({
		request: authz.createAuthorizationRequest(op, client.client, {
			omit: { nonce: "NOT adding nonce to request object" },
		}),
		placeholder: authz.expectRequestMissingNonceErrorPage("OIDCC-3.2.2.1", "OIDCC-3.3.2.11"),
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
			authz.checkErrorFromAuthorizationEndpointErrorInvalidRequest(response, "OIDCC-3.2.2.1", "OIDCC-3.3.2.11"),
		);
	});
}

/** upstream: openid/OIDCCServerTestClientSecretPost.java */
export async function oidccServerClientSecretPost({ op, configureClient }: ConfigureClientFixtures): Promise<void> {
	// a static client: the configuration's `client_secret_post` client, which supports this client authentication
	const client = await configureClient({ staticConfigKey: "client_secret_post" });
	const request = await makeRequest(op, client);
	const response = await authz.authorize(op, request);
	await completeAuthorizationFlow(op, client, request, response);
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
	const request = await makeRequest(op, client);
	const response = await authz.authorize(op, request);
	await completeAuthorizationFlow(op, client, request, response, {
		// the standard id_token checks (which verify the signature) do not apply to an unsigned id_token
		performIdTokenValidation: (unsigned) =>
			soft(() => idToken.checkIdTokenSignatureAlgorithm(unsigned, client.registrationRequest ?? {}, "OIDCC-3.1.3.7")),
	});
}

/**
 * An unsigned request object passed by reference (request_uri) is processed, or rejected with
 * request_uri_not_supported.
 *
 * upstream: openid/OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported.java
 */
export async function oidccRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported({
	op,
	configureClient,
}: ConfigureClientFixtures): Promise<void> {
	// the request_uri is registered with the client, so it exists before the registration
	const requestUri = requestObject.createRandomRequestUriWithFragment(op.baseUrl, "OIDCC-6.2");
	const client = await configureClient({
		customize: (registrationRequest) =>
			registration.addRequestUriToDynamicRegistrationRequest(registrationRequest, requestUri.fullUrl),
	});
	// We deliberately skip the hard check for request_uri_parameter_supported here, as we check for a
	// request_uri_not_supported error later.
	skipIfNoneUnsupported(op);

	const request = await makeRequest(op, client, {
		buildRedirect: (_, params) => {
			const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(params);
			const requestObjectJwt = requestObject.serializeRequestObjectWithNullAlgorithm(claims);
			// the OP fetches the request object from the suite
			op.server.on(
				requestUri.path,
				() => new Response(requestObjectJwt, { status: 200, headers: { "content-type": "application/jwt" } }),
			);
			return requestObject.buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(op, params, claims, requestUri);
		},
	});
	const response = await authz.authorize(op, request);

	await completeAuthorizationFlow(op, client, request, response, {
		afterCallbackLocation: () => {
			if (response.params["error"] === "request_uri_not_supported") {
				// we don't check if state is correct here, as state was only passed inside the request object and hence
				// we can't expect the OP to return it
				skipTest(
					"The 'request_uri_not_supported' error from the authorization endpoint indicates that it does not support request_uri (which is permitted behaviour), so request_uri cannot be tested.",
				);
			}
			if (op.variant.server_metadata === "discovery") {
				soft(() => discovery.checkDiscEndpointRequestUriParameterSupported(op.metadata), "warning");
			}
		},
	});
}

/**
 * An unsigned request object passed by value is processed, or rejected with request_not_supported.
 *
 * upstream: openid/OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported.java
 */
export async function oidccUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported({
	op,
	client,
}: ClientFixtures): Promise<void> {
	skipIfNoneUnsupported(op);

	const request = await makeRequest(op, client, {
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
	});
	const response = await authz.authorize(op, request);

	await completeAuthorizationFlow(op, client, request, response, {
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

	await completeAuthorizationFlow(op, client, request, response, {
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
	const request = await makeRequest(
		op,
		client,
		{
			nonceLength: secondClient ? 43 : undefined,
			steps: (params) =>
				authz.addPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess(params, "OIDCC-11"),
		},
		prefix,
	);
	const response = await authz.authorize(op, request);

	const { tokens, refreshToken } = await block(prefix + "Verify authorization endpoint response", async () => {
		const authorization = await handleAuthorizationEndpointResponse(op, client, request, response, { prefix });
		// the module is not applicable to the response types without code
		const code = authorization.code as string;
		const { tokens: result } = await exchangeAuthorizationCode(op, client, request, { ...authorization, code });

		// upstream: sendRefreshTokenRequestAndCheckIdTokenClaims
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
