/**
 * The bodies of RP tests whose upstream module is part of more than one plan (the basic, implicit, hybrid, form post
 * and config plans share most of their modules), and the flows they share. Each plan's spec registers them with the
 * module's title and `// upstream:` comment:
 *
 *   // upstream: openid/client/OIDCCClientTestIdTokenSigAlgNone.java (rp-id_token-sig-none)
 *   test("oidcc-client-test-idtoken-sig-none: ...", shared.idTokenSigNone);
 *
 * A body follows the variant's response_type the way upstream's module does (AbstractOIDCCClientTest): which
 * requests the RP must send, which it must not, and after which one the module finishes.
 */
import * as authz from "../../src/rp/authorization.ts";
import * as discovery from "../../src/rp/discovery.ts";
import * as idToken from "../../src/rp/id-token.ts";
import * as jwks from "../../src/rp/jwks.ts";
import {
	failTest,
	responseTypeParts,
	type EmulatedOp,
	type EmulatedOpOptions,
	type ResponseTypeParts,
} from "../../src/rp/op.ts";
import * as registration from "../../src/rp/registration.ts";
import type { RpClient } from "../../src/rp/registration.ts";
import type { Rp } from "../../src/rp/rp.ts";
import * as userinfo from "../../src/rp/userinfo.ts";
import { randomAlphabetic } from "../../src/suite/random.ts";

// ---------------------------------------------------------------------------------------------------------------
// the flows

/** response_type=id_token: no access token, so no token or userinfo request */
function isIdTokenOnly(responseType: ResponseTypeParts): boolean {
	return responseType.includesIdToken && !responseType.includesCode && !responseType.includesToken;
}

/**
 * The request after which upstream's module finishes: the userinfo request, or for response_type=id_token (no
 * access token) the jwks request the RP verifies the id_token with ("test may never end if the client caches the
 * jwks").
 *
 * upstream: AbstractOIDCCClientTest.finishTestIfAllRequestsAreReceived
 */
export function finishingRequest(op: EmulatedOp): "userinfo" | "jwks" {
	return isIdTokenOnly(op.responseType) ? "jwks" : "userinfo";
}

/**
 * A successful login with the variant's response type, up to the request that finishes the module: the
 * authorization request; the token request when the code is the only way to an access token (code, code id_token;
 * with code token / code id_token token the RP may use the access token from the authorization response); then the
 * userinfo request, or for response_type=id_token the jwks request.
 *
 * upstream: AbstractOIDCCClientTest (handleClientRequestForPath, finishTestIfAllRequestsAreReceived)
 */
export async function expectLogin(op: EmulatedOp): Promise<void> {
	await op.expect("authorization");
	if (op.responseType.includesCode && !op.responseType.includesToken) {
		await op.expect("token");
	}
	await op.expect(finishingRequest(op));
}

/** What a module built on upstream's AbstractOIDCCClientTestExpectingNothingInvalidIdToken says when the RP goes on */
interface ExpectingNothing {
	/** upstream getAuthorizationCodeGrantTypeErrorMessage */
	tokenEndpointMessage: string;
	/** upstream getHandleUserinfoEndpointRequestErrorMessage */
	userinfoEndpointMessage: string;
	/** upstream isInvalidSignature: an id_token from the token endpoint need not be verified */
	invalidSignature?: boolean;
	/**
	 * upstream isAuthorizationCodeRequestUnexpected: the RP got the defective id_token from the authorization endpoint,
	 * so it must not exchange the code (default: the response type includes id_token)
	 */
	authorizationCodeRequestUnexpected?: (responseType: ResponseTypeParts) => boolean;
}

function authorizationCodeRequestUnexpected(responseType: ResponseTypeParts, m: ExpectingNothing): boolean {
	return m.authorizationCodeRequestUnexpected
		? m.authorizationCodeRequestUnexpected(responseType)
		: responseType.includesIdToken;
}

/**
 * The emulated OP of the modules built on upstream's AbstractOIDCCClientTestExpectingNothingInvalidIdToken: once the
 * RP has the defective id_token it must stop. A token request fails the test when the id_token came from the
 * authorization endpoint; a userinfo request always does, except that an invalid signature on an id_token from the
 * token endpoint (which clients need not verify) skips the test.
 *
 * upstream: AbstractOIDCCClientTestExpectingNothingInvalidIdToken (authorizationCodeGrantType,
 * handleUserinfoEndpointRequest)
 */
function expectingNothingOptions(rp: Rp, m: ExpectingNothing): EmulatedOpOptions {
	const responseType = responseTypeParts(rp.variant.response_type);
	return {
		onCodeExchange: () => {
			if (authorizationCodeRequestUnexpected(responseType, m)) {
				failTest(m.tokenEndpointMessage);
			}
		},
		onUserinfoRequest: () => {
			if (m.invalidSignature && !responseType.includesIdToken) {
				rp.skipTest(
					"The client continued and called the userinfo endpoint after receiving an id token with an invalid signature from the token endpoint. This is acceptable as clients are not required to validate the signatures on id tokens received over a TLS protected connection.",
				);
			}
			failTest(m.userinfoEndpointMessage);
		},
	};
}

/**
 * The flow of the same modules: the authorization request, the token request unless it is unexpected, then
 * upstream's waitTimeoutSeconds timer (startWaitingForTimeout): the RP must reject the id_token and stop, no further
 * request may come. With response_type=id_token the module finishes as soon as the RP fetched the keys to verify the
 * id_token (finishTestIfAllRequestsAreReceived).
 *
 * upstream: AbstractOIDCCClientTestExpectingNothingInvalidIdToken (handleAuthorizationEndpointRequest,
 * authorizationCodeGrantType)
 */
async function expectNothingAfterInvalidIdToken(op: EmulatedOp, rp: Rp, m: ExpectingNothing): Promise<void> {
	await op.expect("authorization");
	if (!authorizationCodeRequestUnexpected(op.responseType, m)) {
		await op.expect("token");
	}
	await op.waitFor(finishingRequest(op), rp.waitTimeoutSeconds);
}

/**
 * The body of a module built on AbstractOIDCCClientTestExpectingNothingInvalidIdToken: the OP issues the defective
 * id_token (`options`), the RP under test logs in and must stop once it has it.
 */
async function expectingNothingInvalidIdToken(
	rp: Rp,
	options: EmulatedOpOptions,
	expecting: ExpectingNothing,
): Promise<void> {
	const op = await rp.start({ ...options, ...expectingNothingOptions(rp, expecting) });
	const client = rp.driveClient();
	await op.clientRegistered();
	await expectNothingAfterInvalidIdToken(op, rp, expecting);
	await client;
}

// ---------------------------------------------------------------------------------------------------------------
// the modules (each spec carries the upstream reference: openid/client/<Module>.java)

/**
 * The emulated OP of oidcc-client-test (openid/client/OIDCCClientTest.java): the default flow with the nonce
 * interoperability check. The RP plans' test starts it, and so does the suite-vs-suite project, whose OP tests
 * run against this suite's own emulated OP (tests/suite-target.ts).
 */
export function oidccClientTestOptions(): EmulatedOpOptions {
	return { checkNonce: authz.checkNonceInteroperability };
}

/** The RP test modules a configuration's `suite_target.module` can name: the options of their emulated OP */
export const emulatedOpModules: Record<string, () => EmulatedOpOptions> = {
	"oidcc-client-test": oidccClientTestOptions,
};

/** oidcc-client-test: the RP logs in with the response type and calls the userinfo endpoint (OIDCCClientTest) */
export async function oidccClientTest({ rp }: { rp: Rp }): Promise<void> {
	// the module's emulated OP; the suite-vs-suite project serves the OP tests with the same one
	const op = await rp.start(oidccClientTestOptions());
	const client = rp.driveClient();
	await op.clientRegistered();
	// upstream finishes the test after the userinfo request (response_type=id_token: after the jwks request)
	await expectLogin(op);
	await client;
}

/** oidcc-client-test-invalid-iss: the RP rejects an id_token whose iss is not the issuer (OIDCCClientTestInvalidIssuerInIdToken) */
export async function invalidIss({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{ idTokenClaims: (claims) => idToken.addInvalidIssValueToIdToken(claims, "OIDCC-3.1.3.7") },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token with an invalid iss claim from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid iss claim.",
		},
	);
}

/** oidcc-client-test-missing-sub: the RP rejects an id_token without sub (OIDCCClientTestMissingSubInIdToken) */
export async function missingSub({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{ idTokenClaims: (claims) => idToken.removeSubFromIdToken(claims, "OIDCC-2") },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token without a sub value from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token without a sub value.",
		},
	);
}

/** oidcc-client-test-invalid-aud: the RP rejects an id_token whose aud is not its client_id (OIDCCClientTestInvalidAudInIdToken) */
export async function invalidAud({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{ idTokenClaims: (claims) => idToken.addInvalidAudValueToIdToken(claims, "OIDCC-3.1.3.7", "OIDCC-2") },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token with an invalid aud claim from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid aud claim.",
		},
	);
}

/** oidcc-client-test-missing-iat: the RP rejects an id_token without iat (OIDCCClientTestMissingIatInIdToken) */
export async function missingIat({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{ idTokenClaims: (claims) => idToken.removeIatFromIdToken(claims, "OIDCC-2") },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token with no iat claim from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with no iat claim.",
		},
	);
}

/**
 * oidcc-client-test-kid-absent-single-jwks: the RP verifies an id_token without kid with the only matching key
 * (OIDCCClientTestKidAbsentSingleJwks)
 */
export async function kidAbsentSingleJwks({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		// without the unusable extra keys: the published JWKS must contain a single key of each type, without kid
		serverJwks: async () => {
			const keys = jwks.oidccGenerateServerJWKsSingleSigningKeyWithNoKeyId("OIDCC-10.1");
			await jwks.validateServerSigningKeys(keys);
			return keys;
		},
		signingAlg: () => idToken.setServerSigningAlgToRS256(),
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await expectLogin(op);
	await client;
}

/**
 * oidcc-client-test-kid-absent-multiple-jwks: the RP rejects an id_token without kid or finds the key among several
 * (OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks)
 */
export async function kidAbsentMultipleJwks({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		// without the unusable extra keys: the published JWKS must contain several possible keys, without kid
		serverJwks: async () => {
			const keys = jwks.oidccGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds("OIDCC-10.1");
			await jwks.validateServerSigningKeys(keys);
			return keys;
		},
		// RS256 always: the test would not work with HS* or none
		signingAlg: () => idToken.setServerSigningAlgToRS256(),
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await op.expect("authorization");
	// upstream waits from the moment the RP has the id_token: the authorization response, else the token response
	if (!op.responseType.includesIdToken) {
		await op.expect("token");
	}
	// both are fine: the RP rejects the id_token (no kid to pick the key by), or tries the keys and goes on
	await op.waitFor(finishingRequest(op), rp.waitTimeoutSeconds);
	await client;
}

/** oidcc-client-test-idtoken-sig-rs256: the RP accepts an id_token signed with RS256 (OIDCCClientTestIdTokenSignedUsingRS256) */
export async function idTokenSigRs256({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		serverConfiguration: discovery.oidccGenerateServerConfigurationIdTokenSigningAlgRS256Only,
		registrationSteps: (c) => registration.setClientIdTokenSignedResponseAlgToRS256(c),
		signingAlg: () => idToken.setServerSigningAlgToRS256("OIDCR-2"),
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await expectLogin(op);
	await client;
}

/**
 * oidcc-client-test-idtoken-sig-none: the RP accepts an unsigned id_token from the token endpoint, or stops
 * (OIDCCClientTestIdTokenSigAlgNone; code flow only)
 */
export async function idTokenSigNone({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		registrationSteps: (c) => {
			registration.setClientIdTokenSignedResponseAlgToNone(c);
			registration.setClientGrantTypesToAuthorizationCodeOnly(c);
		},
		signingAlg: () => idToken.setServerSigningAlgToNone(),
		checkResponseType: (params) => authz.ensureResponseTypeIs(params, "code", "OIDCR-2"),
		signIdToken: (claims) => idToken.signIdTokenWithAlgNone(claims),
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await op.expect("authorization");
	await op.expect("token");
	// clients are not required to support unsigned id_tokens: the RP either calls userinfo or stops
	const info = await op.waitFor("userinfo", rp.waitTimeoutSeconds);
	if (info == null) {
		rp.skipTest(
			"Client did not send a userinfo request after receiving an unsigned id_token. As clients are not required to support unsigned (alg: none) id_tokens this is okay.",
		);
	}
	await client;
}

/**
 * oidcc-client-test-invalid-sig-rs256: the RP rejects an id_token with an invalid RS256 signature
 * (OIDCCClientTestInvalidIdTokenSignatureWithRS256)
 */
export async function invalidSigRs256({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{
			serverConfiguration: discovery.oidccGenerateServerConfigurationIdTokenSigningAlgRS256Only,
			registrationSteps: (c) => registration.setClientIdTokenSignedResponseAlgToRS256(c),
			signingAlg: () => idToken.setServerSigningAlgToRS256(),
			idTokenSignature: (token) => idToken.invalidateIdTokenSignature(token, "OIDCC-3.1.3.7", "OIDCC-3.2.2.11"),
		},
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token with an invalid signature from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid signature.",
			// an id_token from the token endpoint (TLS) need not be validated (OIDCC-3.1.3.7 step 6)
			invalidSignature: true,
		},
	);
}

/**
 * oidcc-client-test-userinfo-invalid-sub: the RP gets a userinfo response whose sub is not the id_token's
 * (OIDCCClientTestInvalidSubInUserinfoResponse; not for response_type=id_token)
 */
export async function userinfoInvalidSub({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		userinfo: (response) => userinfo.changeSubInUserInfoResponseToBeInvalid(response, "OIDCC-5.3.2"),
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	// the suite cannot see whether the RP rejects the response: the test finishes after the userinfo request
	await expectLogin(op);
	await client;
}

/** oidcc-client-test-nonce-invalid: the RP rejects an id_token whose nonce is not the one it sent (OIDCCClientTestNonceInvalid) */
export async function nonceInvalid({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{ idTokenClaims: (claims) => idToken.addInvalidNonceValueToIdToken(claims, "OIDCC-2") },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token with an invalid nonce value from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid nonce value.",
		},
	);
}

/**
 * oidcc-client-test-scope-userinfo-claims: the RP requests claims with the profile, email, phone or address scope
 * (OIDCCClientTestScopeUserInfoClaims)
 */
export async function scopeUserinfoClaims({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		checkAuthorizationRequest: (_params, scope) => authz.ensureScopeContainsAtLeastOneOfProfileEmailPhoneAddress(scope),
		idTokenClaims: (claims, { responseType, userInfo, authorization }) => {
			// without an access token (response_type=id_token) the claims are returned in the id_token
			if (isIdTokenOnly(responseType)) {
				const claimsForScopes = userinfo.filterUserInfoForScopes(userInfo, authorization?.scope ?? "", "OIDCC-5.4");
				idToken.addUserinfoClaimsToIdTokenClaims(claims, claimsForScopes, "OIDCC-5.4");
			}
		},
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await expectLogin(op);
	await client;
}

/**
 * oidcc-client-test-client-secret-basic: the RP authenticates at the token endpoint with client_secret_basic
 * (OIDCCClientTestClientSecretBasic; not for the response types without a code)
 */
export async function clientSecretBasic({ rp }: { rp: Rp }): Promise<void> {
	// client_secret_basic whatever client authentication the configuration selects
	const op = await rp.start({ clientAuthType: "client_secret_basic" });
	const client = rp.driveClient();
	await op.clientRegistered();
	await expectLogin(op);
	await client;
}

/**
 * oidcc-client-test-nonce-unless-code-flow: the RP sends a nonce with the implicit and hybrid response types
 * (OIDCCClientTestNonce; not for response_type=code)
 */
export async function nonceUnlessCodeFlow({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		// the nonce is required whatever the response type (the default only requires it with an id_token)
		extractNonce: (params) => authz.extractNonceFromAuthorizationRequest(params, "OIDCC-3.1.2.1"),
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await expectLogin(op);
	await client;
}

/** at_hash checks only apply to an id_token issued with an access token at the authorization endpoint */
const athashCodeRequestUnexpected = (responseType: ResponseTypeParts) =>
	responseType.includesIdToken && responseType.includesToken;

/**
 * oidcc-client-test-invalid-athash: the RP rejects an id_token whose at_hash does not match the access token
 * (OIDCCClientTestInvalidAtHashInIdToken; id_token token, code id_token token)
 */
export async function invalidAtHash({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{
			addAtHashToIdToken: (claims, atHash) => idToken.addInvalidAtHashValueToIdToken(claims, atHash, "OIDCC-3.3.2.11"),
		},
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token with an invalid at_hash value from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid at_hash value.",
			authorizationCodeRequestUnexpected: athashCodeRequestUnexpected,
		},
	);
}

/**
 * oidcc-client-test-missing-athash: the RP rejects an id_token issued with an access token but without at_hash
 * (OIDCCClientTestMissingAtHashInIdToken; id_token token, code id_token token)
 */
export async function missingAtHash({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		// do not add it
		{ addAtHashToIdToken: () => {} },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token without an at_hash value from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token without an at_hash value.",
			authorizationCodeRequestUnexpected: athashCodeRequestUnexpected,
		},
	);
}

/**
 * oidcc-client-test-invalid-chash: the RP rejects an id_token whose c_hash does not match the code
 * (OIDCCClientTestInvalidCHashInIdToken; code id_token, code id_token token)
 */
export async function invalidCHash({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		{ addCHashToIdToken: (claims, cHash) => idToken.addInvalidCHashValueToIdToken(claims, cHash, "OIDCC-3.3.2.10") },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token with an invalid c_hash value from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid c_hash value.",
		},
	);
}

/**
 * oidcc-client-test-missing-chash: the RP rejects an id_token issued with a code but without c_hash
 * (OIDCCClientTestMissingCHashInIdToken; code id_token, code id_token token)
 */
export async function missingCHash({ rp }: { rp: Rp }): Promise<void> {
	await expectingNothingInvalidIdToken(
		rp,
		// do nothing, don't add it
		{ addCHashToIdToken: () => {} },
		{
			tokenEndpointMessage:
				"Client has incorrectly called token_endpoint after receiving an id_token without a c_hash value from the authorization_endpoint.",
			userinfoEndpointMessage:
				"Client has incorrectly called userinfo_endpoint after receiving an id_token without a c_hash value.",
		},
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the configuration modules (openid/client/config/<Module>.java), in the dynamic and the config plan

/**
 * oidcc-client-test-discovery-openid-config: the RP fetches the OP's configuration from
 * .well-known/openid-configuration (OIDCCClientTestDiscoveryOpenIDConfiguration)
 */
export async function discoveryOpenIdConfig({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start();
	const client = rp.driveClient();
	// upstream finishes the test after the discovery request
	await op.expect("discovery");
	await client;
}

/**
 * oidcc-client-test-discovery-jwks-uri-keys: the RP fetches the keys from the jwks_uri of the OP's configuration
 * (OIDCCClientTestDiscoveryJwksUriKeys)
 */
export async function discoveryJwksUriKeys({ rp }: { rp: Rp }): Promise<void> {
	const randomJwksUriSuffix = randomAlphabetic(10);
	const op = await rp.start({
		// a jwks_uri that changes with every run (the keys are served there only): the RP has to use the configuration
		serverConfiguration: (baseUrl) => {
			const server = discovery.oidccGenerateServerConfiguration(baseUrl);
			discovery.addRandomJwksUriToServerConfiguration(server, randomJwksUriSuffix);
			return server;
		},
		// upstream checkIfDiscoveryCalled / checkIfJWKCalled: nothing before discovery, no userinfo before the keys
		onRequest: (endpoint, request, { received }) => {
			if (endpoint === "discovery" || endpoint === "webfinger") {
				return;
			}
			if (received("discovery") === 0) {
				failTest("Got unexpected HTTP call to " + request.path + " before the discovery endpoint call");
			}
			if (endpoint === "userinfo" && received("jwks") === 0) {
				failTest("Got unexpected HTTP call to " + request.path + " before the jwks endpoint call");
			}
		},
	});
	const client = rp.driveClient();
	// upstream finishes the test after the discovery and the jwks requests
	await op.expect("discovery");
	await op.expect("jwks");
	await client;
}

/**
 * oidcc-client-test-discovery-issuer-mismatch: the RP stops when the configuration's issuer is not the one
 * WebFinger returned (OIDCCClientTestDiscoveryIssuerMismatch)
 */
export async function discoveryIssuerMismatch({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		onRequest: (endpoint, _request, { metadata }) => {
			if (endpoint === "discovery") {
				discovery.changeIssuerInServerConfigurationToBeInvalid(metadata);
			}
			if (endpoint === "authorization") {
				failTest(
					"The client is expected to detect the issuer mismatch and stop" +
						" the flow after fetching OpenID Provider configuration.",
				);
			}
		},
	});
	const client = rp.driveClient();
	await op.expect("discovery");
	// the RP must detect the mismatch and stop: no authorization request within waitTimeoutSeconds
	await op.waitFor("authorization", rp.waitTimeoutSeconds);
	await client;
}

/**
 * oidcc-client-test-signing-key-rotation-just-before-signing: the RP fetches the OP's keys again to verify an
 * id_token signed with a new key (OIDCCClientTestSigningKeyRotationJustBeforeSigning)
 */
export async function signingKeyRotationJustBeforeSigning({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		// new keys (new kids) right before the id_token is signed
		signIdToken: (claims, emulated) => {
			emulated.keys = jwks.regenerateServerJwks();
			return idToken.oidccSignIdToken(
				claims,
				emulated.keys.jwks,
				emulated.client as RpClient,
				emulated.signingAlg as string,
				"OIDCC-2",
			);
		},
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await op.expect("authorization");
	await op.expect("token");
	// the RP can only verify the id_token with the new keys, then calls userinfo
	await op.expect("userinfo");
	await client;
}

/**
 * oidcc-client-test-signing-key-rotation: the RP logs in twice and fetches the OP's keys again after they were
 * rotated (OIDCCClientTestSigningKeyRotation)
 */
export async function signingKeyRotation({ rp }: { rp: Rp }): Promise<void> {
	const op = await rp.start({
		// the second authorization request: new keys (new kids) sign the second id_token
		onRequest: (endpoint, _request, emulated) => {
			if (endpoint === "authorization" && emulated.received("authorization") > 0) {
				emulated.keys = jwks.regenerateServerJwks();
			}
		},
		authorizationBlock: ({ received }) =>
			received("authorization") > 0 ? "Second Authorization Request" : "Authorization endpoint",
	});
	const client = rp.driveClient();
	await op.clientRegistered();
	await op.expect("authorization");
	await op.expect("token");
	await op.expect("userinfo");
	// the second login, after the key rotation
	await op.expect("authorization");
	await op.expect("token");
	await op.expect("userinfo");
	// upstream finishes the test after the second userinfo request and the second jwks request
	await op.expect("jwks");
	await op.expect("jwks");
	await client;
}
