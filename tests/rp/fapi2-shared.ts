/**
 * The bodies of the FAPI 2.0 client (RP) test modules (upstream fapi2spfinal/FAPI2SPFinalClientTest*.java), shared
 * by the security profile and the message signing plans (tests/rp/fapi2-security-profile.spec.ts,
 * tests/rp/fapi2-message-signing.spec.ts register them with the module's title and `// upstream:` comment), and
 * the flows they share.
 *
 * The suite plays the FAPI 2 authorization server (rp.startFapi2, src/rp/fapi2.ts): the RP under test discovers
 * it, pushes its authorization request (PAR, with a DPoP proof and a private_key_jwt assertion), is redirected
 * back with a code (plain, with iss, or a JARM response), exchanges it at the token endpoint (DPoP-bound) and calls
 * the accounts resource with the DPoP-bound access token. With DPoP nonces the first request to the PAR, token and
 * resource endpoints is answered with a use_dpop_nonce challenge and repeated (expectWithDpopNonce).
 */
import * as authz from "../../src/rp/authorization.ts";
import * as discovery from "../../src/rp/discovery.ts";
import * as dpop from "../../src/rp/dpop.ts";
import type { Fapi2As, Fapi2AsOptions } from "../../src/rp/fapi2.ts";
import * as idToken from "../../src/rp/id-token.ts";
import * as jarm from "../../src/rp/jarm.ts";
import type { Rp } from "../../src/rp/rp.ts";
import * as token from "../../src/rp/token.ts";
import { checkDistinctKeyIdValueInServerJWKs } from "../../src/op/jwks.ts";
import { skipped, soft } from "../../src/suite/conditions.ts";

// ---------------------------------------------------------------------------------------------------------------
// the flows

/**
 * The RP's request to a DPoP endpoint: a request without the server's nonce gets a use_dpop_nonce challenge and
 * the RP repeats it with the nonce (upstream: the PAR, token and resource endpoints answer each request on its own;
 * the test follows the one that was accepted).
 */
export async function expectWithDpopNonce<E extends "par" | "token" | "accounts" | "userinfo">(
	as: Fapi2As,
	endpoint: E,
) {
	let event = await as.expect(endpoint);
	while (event.dpopNonceError != null) {
		event = await as.expect(endpoint);
	}
	return event;
}

/**
 * A complete FAPI 2 flow, up to the resource request that finishes the module: PAR, the authorization request,
 * the token request, the accounts request (upstream resourceEndpointCallComplete).
 */
export async function expectLogin(as: Fapi2As): Promise<void> {
	await expectWithDpopNonce(as, "par");
	await as.expect("authorization");
	await expectWithDpopNonce(as, "token");
	await expectWithDpopNonce(as, "accounts");
}

/** A module's body: the authorization server with its options, the RP under test, the flow */
async function run(rp: Rp, options: Fapi2AsOptions, flow: (as: Fapi2As) => Promise<void>): Promise<void> {
	const as = await rp.startFapi2(options);
	const client = rp.driveClient();
	await flow(as);
	await client;
}

/**
 * The modules built on upstream's AbstractFAPI2SPFinalClientExpectNothingAfterIdTokenIssued: once the RP has the
 * defective id_token from the token endpoint it must stop; any further request is refused with the fault
 * (getIdTokenFaultErrorMessage) and fails the test.
 */
async function expectNothingAfterIdTokenIssued(rp: Rp, fault: string, options: Fapi2AsOptions): Promise<void> {
	await run(
		rp,
		{
			...options,
			afterIdTokenIssued: (as) => as.startWaitingForTimeout(),
			responseClientMustStopAfter: `an invalid id_token (${fault})`,
		},
		async (as) => {
			await expectWithDpopNonce(as, "par");
			await as.expect("authorization");
			await expectWithDpopNonce(as, "token");
			// the RP must reject the id_token and stop: no resource request within waitTimeoutSeconds
			await as.waitFor("accounts", rp.waitTimeoutSeconds);
		},
	);
}

/**
 * The modules built on upstream's AbstractFAPI2SPFinalClientExpectNothingAfterAuthorizationResponse: once the RP
 * has the invalid authorization response it must stop; a token request is refused with the fault
 * (getAuthorizationResponseErrorMessage) and fails the test.
 */
async function expectNothingAfterAuthorizationResponse(rp: Rp, fault: string, options: Fapi2AsOptions): Promise<void> {
	await run(
		rp,
		{
			...options,
			afterAuthorizationResponse: (as) => as.startWaitingForTimeout(),
			responseClientMustStopAfter: `an invalid authorization response (${fault})`,
		},
		async (as) => {
			await expectWithDpopNonce(as, "par");
			await as.expect("authorization");
			// the RP must reject the response and stop: no token request within waitTimeoutSeconds
			await as.waitFor("token", rp.waitTimeoutSeconds);
		},
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the happy path (FAPI2SPFinalClientTestHappyPath)

/**
 * The checks of the happy path on the authorization request before the response is created: the nonce (OpenID
 * Connect) or the state (plain OAuth) only has URL safe characters and is not too long.
 *
 * upstream: FAPI2SPFinalClientTestHappyPath.createAuthorizationEndpointResponse
 */
function checkNonceOrStateInteroperability(effective: Record<string, unknown>, as: Fapi2As): void {
	if (as.authorization?.openidRequested) {
		authz.checkNonceInteroperability(as.authorization.nonce);
		return;
	}
	if (effective["state"] == null) {
		skipped("CheckForInvalidCharsInState", { element: ["effective_authorization_endpoint_request", "state"] });
		skipped("CheckStateLength", { element: ["effective_authorization_endpoint_request", "state"] });
		return;
	}
	soft(() => authz.checkForInvalidCharsInState(effective), "warning");
	soft(() => authz.checkStateLength(effective), "warning");
}

/** The authorization server of the happy path: the kid check of its keys and the nonce / state checks */
function happyPathOptions(): Fapi2AsOptions {
	return {
		onConfigurationCompleted: (as) =>
			soft(() => checkDistinctKeyIdValueInServerJWKs(as.keys.jwks, "RFC7517-4.5", "FAPI2-SP-FINAL-5.4.2-3"), "warning"),
		beforeAuthorizationResponse: checkNonceOrStateInteroperability,
	};
}

/** fapi2-security-profile-final-client-test-happy-path: the RP completes the PAR, DPoP-bound code flow and calls the resource (FAPI2SPFinalClientTestHappyPath) */
export async function happyPath({ rp }: { rp: Rp }): Promise<void> {
	await run(rp, happyPathOptions(), expectLogin);
}

/** fapi2-security-profile-final-client-test-happy-path-no-dpop-nonce: the flow without DPoP nonces (FAPI2SPFinalClientTestHappyPathNoDpopNonce) */
export async function happyPathNoDpopNonce({ rp }: { rp: Rp }): Promise<void> {
	await run(
		rp,
		{
			...happyPathOptions(),
			requireAuthorizationServerEndpointDpopNonce: false,
			requireResourceServerEndpointDpopNonce: false,
		},
		expectLogin,
	);
}

/**
 * fapi2-security-profile-final-client-test-happy-path-no-mtls-endpoint-aliases: the flow against a server that
 * publishes no mtls_endpoint_aliases (FAPI2SPFinalClientTestHappyPathNoMtlsEndpointAliases; with private_key_jwt
 * and DPoP no endpoint moves to the mTLS listener)
 */
export async function happyPathNoMtlsEndpointAliases({ rp }: { rp: Rp }): Promise<void> {
	await run(
		rp,
		{
			...happyPathOptions(),
			adjustServerConfigurationForMtlsEndpointAliasesVariant: (server) =>
				discovery.removeMtlsEndpointAliasesFromServerConfiguration(server, "RFC8705-5"),
		},
		expectLogin,
	);
}

// ---------------------------------------------------------------------------------------------------------------
// discovery

/** fapi2-security-profile-final-client-test-discovery-issuer-mismatch: the RP stops when the discovery document's issuer is not the url it came from (FAPI2SPFinalClientTestDiscoveryIssuerMismatch) */
export async function discoveryIssuerMismatch({ rp }: { rp: Rp }): Promise<void> {
	await run(
		rp,
		{
			// Add invalid issuer to server configuration.
			onConfigurationCompleted: (as) => discovery.changeIssuerInServerConfigurationToBeInvalid(as.metadata),
			afterDiscoveryResponse: (as) => as.startWaitingForTimeout(),
			responseClientMustStopAfter:
				"a discovery document whose issuer does not match the URL the document was retrieved from",
		},
		async (as) => {
			await as.expect("discovery");
			// the RP must detect the mismatch and stop: no PAR request within waitTimeoutSeconds
			await as.waitFor("par", rp.waitTimeoutSeconds);
		},
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the id_token from the token endpoint

/** fapi2-security-profile-final-client-test-invalid-iss (FAPI2SPFinalClientTestInvalidIss) */
export async function invalidIss({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "invalid iss value", {
		addCustomValuesToIdToken: (claims) => idToken.addInvalidIssValueToIdToken(claims, "OIDCC-3.1.3.7-2"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-aud (FAPI2SPFinalClientTestInvalidAud) */
export async function invalidAud({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "invalid aud value", {
		addCustomValuesToIdToken: (claims) => idToken.addInvalidAudValueToIdToken(claims, "OIDCC-3.1.3.7-3"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-secondary-aud (FAPI2SPFinalClientTestInvalidSecondaryAud) */
export async function invalidSecondaryAud({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "aud is an array that contains an untrusted value", {
		addCustomValuesToIdToken: (claims) => idToken.addUntrustedSecondAudValueToIdToken(claims, "OIDCC-3.1.3.7-3"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-null-alg (FAPI2SPFinalClientTestInvalidNullAlg) */
export async function invalidNullAlg({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "null alg value", {
		addCustomSignatureOfIdToken: (_jwt, claims) => idToken.signIdTokenWithNullAlgorithm(claims, "OIDCC-3.1.3.7-7"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-alternate-alg (FAPI2SPFinalClientTestInvalidAlternateAlg) */
export async function invalidAlternateAlg({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "signed using alt RS256 alg.", {
		addCustomSignatureOfIdToken: (jwt, _claims, as) =>
			idToken.forceIdTokenToBeSignedWithAltRS256(jwt, as.altJwks, "OIDCC-3.1.3.7-8"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-expired-exp (FAPI2SPFinalClientTestInvalidExpiredExp) */
export async function invalidExpiredExp({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "expired exp value", {
		addCustomValuesToIdToken: (claims) => idToken.addInvalidExpiredExpValueToIdToken(claims, "OIDCC-3.1.3.7-9"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-missing-exp (FAPI2SPFinalClientTestInvalidMissingExp) */
export async function invalidMissingExp({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "missing exp value", {
		addCustomValuesToIdToken: (claims) => idToken.removeExpFromIdToken(claims, "OIDCC-3.1.3.7-9"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-missing-aud (FAPI2SPFinalClientTestInvalidMissingAud) */
export async function invalidMissingAud({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "missing aud value", {
		addCustomValuesToIdToken: (claims) => idToken.removeAudFromIdToken(claims, "OIDCC-3.1.3.7-3"),
	});
}

/** fapi2-security-profile-final-client-test-invalid-missing-iss (FAPI2SPFinalClientTestInvalidMissingIss) */
export async function invalidMissingIss({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "missing iss value", {
		addCustomValuesToIdToken: (claims) => idToken.removeIssFromIdToken(claims, "OIDCC-3.1.3.7-2"),
	});
}

/** fapi2-security-profile-final-client-test-valid-aud-as-array: the RP accepts an aud with one value as an array (FAPI2SPFinalClientTestValidAudAsArray) */
export async function validAudAsArray({ rp }: { rp: Rp }): Promise<void> {
	await run(
		rp,
		{
			addCustomValuesToIdToken: (claims) => idToken.addAudValueAsArrayToIdToken(claims, "OIDCC-3.1.3.7-3"),
			// signed again as is, so the single-valued aud array stays an array
			addCustomSignatureOfIdToken: (_jwt, claims, as) => idToken.signIdTokenBypassingNimbusChecks(claims, as.keys.jwks),
		},
		expectLogin,
	);
}

/** fapi2-security-profile-final-client-test-invalid-nonce (FAPI2SPFinalClientTestInvalidNonce) */
export async function invalidNonce({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterIdTokenIssued(rp, "invalid nonce value", {
		addCustomValuesToIdToken: (claims) => idToken.addInvalidNonceValueToIdToken(claims, "OIDCC-3.1.3.7-11"),
	});
}

/**
 * fapi2-security-profile-final-client-test-invalid-missing-nonce: the RP rejects an id_token without the nonce it
 * sent; skipped when it sent none (FAPI2SPFinalClientTestInvalidMissingNonce)
 */
export async function invalidMissingNonce({ rp }: { rp: Rp }): Promise<void> {
	let issuedMissingNonce = false;
	await run(
		rp,
		{
			endTestIfRequiredParametersAreMissing: (effective) => {
				if (!effective["nonce"]) {
					rp.skipTest(
						"This test is being skipped as it relies on the client supplying an OPTIONAL nonce value - since none is supplied, this can not be tested. PKCE prevents CSRF so this is acceptable and will not prevent certification.",
					);
				}
			},
			addCustomValuesToIdToken: (claims) => {
				if (claims["nonce"]) {
					idToken.removeNonceFromIdToken(claims, "OIDCC-3.1.3.7-11");
					issuedMissingNonce = true;
				}
			},
			afterIdTokenIssued: (as) => {
				if (issuedMissingNonce) {
					as.startWaitingForTimeout();
				}
			},
			responseClientMustStopAfter: "an invalid id_token (missing nonce value)",
		},
		async (as) => {
			await expectWithDpopNonce(as, "par");
			await as.expect("authorization");
			await expectWithDpopNonce(as, "token");
			await as.waitFor("accounts", rp.waitTimeoutSeconds);
		},
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the authorization response

/** fapi2-security-profile-final-client-test-invalid-authorization-response-iss (FAPI2SPFinalClientTestInvalidAuthorizationResponseIss) */
export async function invalidAuthorizationResponseIss({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Returned invalid iss", {
		addCustomValuesToAuthorizationResponse: (params, as) =>
			soft(() => authz.addInvalidIssToAuthorizationEndpointResponseParams(params, as.issuer), "info"),
	});
}

/** fapi2-security-profile-final-client-test-remove-authorization-response-iss (FAPI2SPFinalClientTestRemoveAuthorizationResponseIss) */
export async function removeAuthorizationResponseIss({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Removed iss from authorization response", {
		addCustomValuesToAuthorizationResponse: (params) =>
			soft(() => authz.removeIssFromAuthorizationEndpointResponseParams(params), "info"),
	});
}

/** fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails (FAPI2SPFinalClientTestEnsureAuthorizationResponseWithInvalidStateFails) */
export async function invalidState({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Added invalid state to the authorization response", {
		addCustomValuesToAuthorizationResponse: (params) =>
			soft(() => authz.addInvalidStateToAuthorizationEndpointResponseParams(params), "info"),
	});
}

/**
 * fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-missing-state-fails: the RP
 * rejects a response without the state it sent; skipped when it sent none
 * (FAPI2SPFinalClientTestEnsureAuthorizationResponseWithInvalidMissingStateFails)
 */
export async function missingState({ rp }: { rp: Rp }): Promise<void> {
	let removedState = false;
	await run(
		rp,
		{
			endTestIfRequiredParametersAreMissing: (effective) => {
				if (!effective["state"]) {
					rp.skipTest(
						"This test is being skipped as it relies on the client supplying an OPTIONAL state value - since none is supplied, this can not be tested. PKCE prevents CSRF so this is acceptable and will not prevent certification.",
					);
				}
			},
			addCustomValuesToAuthorizationResponse: (params) => {
				if (params["state"]) {
					soft(() => authz.removeStateFromAuthorizationEndpointResponseParams(params), "info");
					removedState = true;
				}
			},
			afterAuthorizationResponse: (as) => {
				if (removedState) {
					as.startWaitingForTimeout();
				}
			},
			responseClientMustStopAfter: "an invalid authorization response (Removed state from the authorization response)",
		},
		async (as) => {
			await expectWithDpopNonce(as, "par");
			await as.expect("authorization");
			await as.waitFor("token", rp.waitTimeoutSeconds);
		},
	);
}

// ---------------------------------------------------------------------------------------------------------------
// the token endpoint and the resource

/** fapi2-security-profile-final-client-test-token-endpoint-response-without-expires_in (FAPI2SPFinalClientTestTokenEndpointResponseWithoutExpiresIn) */
export async function tokenEndpointResponseWithoutExpiresIn({ rp }: { rp: Rp }): Promise<void> {
	await run(
		rp,
		{
			afterAccessTokenIssued: (as) => {
				soft(() => token.removeAccessTokenExpiration(), "info");
				as.accessTokenExpiration = null;
			},
		},
		expectLogin,
	);
}

/** fapi2-security-profile-final-client-test-token-type-case-insensitivity: the RP accepts token_type "dpOp" (FAPI2SPFinalClientTestTokenTypeCaseInsenstivity) */
export async function tokenTypeCaseInsensitivity({ rp }: { rp: Rp }): Promise<void> {
	await run(
		rp,
		{
			afterAccessTokenIssued: (as) => {
				as.tokenType = soft(() => token.setTokenResponseTokenTypeToInvertedCase(as.tokenType), "info") ?? as.tokenType;
			},
		},
		expectLogin,
	);
}

/** fapi2-security-profile-final-client-test-rs-dpop-auth-scheme-case-insensitivity: the RP accepts a "dPoP" use_dpop_nonce challenge (FAPI2SPFinalClientTestRSDpopAuthSchemeCaseInsenstivity) */
export async function rsDpopAuthSchemeCaseInsensitivity({ rp }: { rp: Rp }): Promise<void> {
	await run(
		rp,
		{ createResourceEndpointDpopErrorResponse: dpop.createResourceEndpointDpopErrorAltSchemeCaseResponse },
		expectLogin,
	);
}

// ---------------------------------------------------------------------------------------------------------------
// JARM (the message signing plan)

/** fapi2-security-profile-final-client-test-ensure-jarm-without-iss-fails (FAPI2SPFinalClientTestEnsureJarmWithoutIssFails) */
export async function jarmWithoutIss({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Removed iss from JARM response", {
		addCustomValuesToJarmResponse: (claims) => soft(() => jarm.removeIssFromJarm(claims), "info"),
	});
}

/** fapi2-security-profile-final-client-test-ensure-jarm-with-invalid-iss-fails (FAPI2SPFinalClientTestEnsureJarmWithInvalidIssFails) */
export async function jarmWithInvalidIss({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Added invalid iss to JARM response", {
		addCustomValuesToJarmResponse: (claims) => soft(() => jarm.addInvalidIssValueToJarm(claims, "JARM-2.1")),
	});
}

/** fapi2-security-profile-final-client-test-ensure-jarm-without-aud-fails (FAPI2SPFinalClientTestEnsureJarmWithoutAudFails) */
export async function jarmWithoutAud({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Removed aud from JARM response", {
		addCustomValuesToJarmResponse: (claims) => soft(() => jarm.removeAudFromJarm(claims), "info"),
	});
}

/** fapi2-security-profile-final-client-test-ensure-jarm-with-invalid-aud-fails (FAPI2SPFinalClientTestEnsureJarmWithInvalidAudFails) */
export async function jarmWithInvalidAud({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Added invalid aud to JARM response", {
		addCustomValuesToJarmResponse: (claims) => soft(() => jarm.addInvalidAudValueToJarm(claims, "JARM-2.1"), "warning"),
	});
}

/** fapi2-security-profile-final-client-test-ensure-jarm-without-exp-fails (FAPI2SPFinalClientTestEnsureJarmWithoutExpFails) */
export async function jarmWithoutExp({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Removed exp from JARM response", {
		addCustomValuesToJarmResponse: (claims) => soft(() => jarm.removeExpFromJarm(claims), "info"),
	});
}

/** fapi2-security-profile-final-client-test-ensure-jarm-with-expired-exp-fails (FAPI2SPFinalClientTestEnsureJarmWithExpiredExpFails) */
export async function jarmWithExpiredExp({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Added expired exp to JARM response", {
		addCustomValuesToJarmResponse: (claims) => soft(() => jarm.addInvalidExpiredExpValueToJarm(claims), "info"),
	});
}

/** fapi2-security-profile-final-client-test-ensure-jarm-with-invalid-sig-fails (FAPI2SPFinalClientTestEnsureJarmWithInvalidSigFails) */
export async function jarmWithInvalidSig({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Signed JARM response with an invalid signature", {
		createJARMResponse: async (claims, as) => {
			const signed = await jarm.signJARMResponse(claims, as.keys.jwks, "JARM-2.2");
			return jarm.encryptJARMResponseIfConfigured(jarm.invalidateJarmSignature(signed), as.client);
		},
	});
}

/** fapi2-security-profile-final-client-test-ensure-jarm-signature-is-not-none (FAPI2SPFinalClientTestEnsureJarmSignatureAlgIsNotNone) */
export async function jarmSignatureIsNotNone({ rp }: { rp: Rp }): Promise<void> {
	await expectNothingAfterAuthorizationResponse(rp, "Signed JARM response with algorithm NONE", {
		createJARMResponse: async (claims, as) =>
			jarm.encryptJARMResponseIfConfigured(jarm.signJarmWithNullAlgorithm(claims), as.client),
	});
}
