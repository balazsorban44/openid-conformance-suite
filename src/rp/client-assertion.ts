/**
 * private_key_jwt client authentication at the emulated authorization server's token and PAR endpoints: the
 * client_assertion the RP sends is extracted, its signature verified with the client's configured keys and its
 * claims checked (RFC 7523 section 3, OIDC Core section 9, PAR section 2).
 *
 * upstream: sequence/as/ValidateClientAuthenticationWithPrivateKeyJWT.java and the conditions it calls
 */
import { condition, soft, type Condition } from "../suite/conditions.ts";
import { ParseException } from "../suite/errors.ts";
import { verifyJwsSignature, type ParsedJwt } from "../suite/jose.ts";
import { jwtStringToJsonObjectForEnvironment, parseSignedJWT } from "../suite/jose-jwt.ts";
import { getString } from "../suite/json.ts";
import type { IncomingRequest } from "../suite/server.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { RpClient } from "./registration.ts";

/** The parsed client_assertion (upstream env "client_assertion": value, header, claims) */
export type ClientAssertion = ParsedJwt;

/** A form parameter read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function formParam(req: IncomingRequest, name: string): string | null {
	const v = req.body_form_params?.[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

/** A numeric claim (Environment.getLong): null when absent or JSON null */
function long(claims: Record<string, unknown>, name: string): number | null {
	const v = claims[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "number") {
		throw new Error(`A number is required for client_assertion claims.${name} but ${typeof v} was found`);
	}
	return Math.trunc(v);
}

/** A string of the server metadata, null when absent */
function serverString(server: ServerMetadata, name: string): string | null {
	const v = server[name];
	return typeof v === "string" ? v : null;
}

/** The token_endpoint of mtls_endpoint_aliases (upstream "server".mtls_endpoint_aliases.token_endpoint) */
function mtlsAlias(server: ServerMetadata, endpoint: string): string | null {
	const aliases = server["mtls_endpoint_aliases"];
	if (aliases == null || typeof aliases !== "object" || Array.isArray(aliases)) {
		return null;
	}
	const v = (aliases as Record<string, unknown>)[endpoint];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/as/ExtractClientAssertion.java */
export function extractClientAssertion(req: IncomingRequest, ...requirements: string[]): ClientAssertion {
	const c: Condition = condition("ExtractClientAssertion", ...requirements);
	const clientAssertionString = formParam(req, "client_assertion");
	if (!clientAssertionString) {
		c.failure("Could not find client assertion in request parameters");
	}
	try {
		const assertion = jwtStringToJsonObjectForEnvironment(clientAssertionString) as unknown as ClientAssertion;
		c.success("Parsed client assertion", { client_assertion: assertion });
		return assertion;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse client assertion", e, { "client assertion": clientAssertionString });
		}
		throw e;
	}
}

/**
 * The assertion is signed with the client's registered token_endpoint_auth_signing_alg, when it has one.
 *
 * upstream: condition/as/EnsureClientAssertionSignatureAlgorithmMatchesRegistered.java
 */
export function ensureClientAssertionSignatureAlgorithmMatchesRegistered(
	assertion: ClientAssertion,
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureClientAssertionSignatureAlgorithmMatchesRegistered", ...requirements);
	try {
		const jwt = parseSignedJWT(assertion.value);
		const expectedAlgName =
			typeof client["token_endpoint_auth_signing_alg"] === "string" ? client["token_endpoint_auth_signing_alg"] : null;
		if (expectedAlgName != null) {
			const actualAlg = String(jwt.header["alg"]);
			if (expectedAlgName === actualAlg) {
				c.success("Client assertion is signed using the registered token_endpoint_auth_signing_alg algorithm", {
					algorithm: expectedAlgName,
				});
			} else {
				c.failure("Client assertion is not signed using the registered token_endpoint_auth_signing_alg algorithm.", {
					expected: expectedAlgName,
					actual: actualAlg,
				});
			}
		} else {
			c.log("token_endpoint_auth_signing_alg is not set for the client, any supported algorithm can be used");
		}
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Invalid client assertion", e, { client_assertion: assertion.value });
		}
		throw e;
	}
}

/**
 * The assertion's signature verifies with a key of the client's configured JWKS (`client.jwks`; a kid is required).
 *
 * upstream: condition/as/ValidateClientAssertionSignature.java (AbstractVerifyJwsSignature)
 */
export async function validateClientAssertionSignature(
	assertion: ClientAssertion,
	client: RpClient,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("ValidateClientAssertionSignature", ...requirements);
	const clientJWKS = client["jwks"];
	if (clientJWKS == null || typeof clientJWKS !== "object" || Array.isArray(clientJWKS)) {
		// UPSTREAM: client.get("jwks").getAsJsonObject() throws for a missing or non-object jwks
		throw new Error("Not a JSON Object: " + JSON.stringify(clientJWKS ?? null));
	}
	await verifyJwsSignature(c, assertion.value, clientJWKS, "client_assertion", true, "client");
}

/** upstream: condition/as/EnsureClientAssertionTypeIsJwt.java */
export function ensureClientAssertionTypeIsJwt(req: IncomingRequest, ...requirements: string[]): void {
	const c: Condition = condition("EnsureClientAssertionTypeIsJwt", ...requirements);
	const assertionType = formParam(req, "client_assertion_type");
	const expected = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	if (expected === assertionType) {
		c.success("Found JWT assertion type", { "assertion type": expected });
		return;
	}
	if (assertionType == null) {
		c.failure("client_assertion_type missing from request parameters", { expected, actual: null });
	}
	c.failure("client_assertion_type does not match JWT", { expected, actual: assertionType });
}

const TIME_SKEW_MILLIS = 5 * 60 * 1000; // 5 minute allowable skew for testing
const ONE_DAY_MILLIS = 60 * 60 * 24 * 1000; // Duration for one day

/**
 * The aud of an assertion at the token endpoint: the issuer, the token endpoint or its mTLS alias.
 *
 * upstream: condition/as/ValidateClientAssertionClaims.java (validateAud)
 */
function validateTokenEndpointAud(c: Condition, assertion: ClientAssertion, server: ServerMetadata): void {
	const issuer = serverString(server, "issuer");
	const tokenEndpoint = serverString(server, "token_endpoint");
	if (!tokenEndpoint) {
		c.failure(
			"Couldn't find issuer or client or token endpoint values in the test configuration to test the assertion",
		);
	}
	const mtlsTokenEndpoint = mtlsAlias(server, "token_endpoint");
	const aud = assertion.claims["aud"];
	if (aud == null) {
		c.failure("Missing aud");
	}
	const tokenEndpoints = [tokenEndpoint];
	if (mtlsTokenEndpoint != null) {
		tokenEndpoints.push(mtlsTokenEndpoint);
	}
	if (Array.isArray(aud)) {
		if (!aud.includes(issuer) && !aud.includes(tokenEndpoint) && !aud.includes(mtlsTokenEndpoint)) {
			c.failure("aud not found", { expected: tokenEndpoints, actual: aud });
		}
	} else {
		const audStr = getString(aud);
		if (audStr !== issuer && audStr !== tokenEndpoint && audStr !== mtlsTokenEndpoint) {
			c.failure("aud mismatch", { expected: tokenEndpoints, actual: aud });
		}
	}
}

/**
 * The aud of an assertion at the PAR endpoint: the issuer, the token endpoint, the PAR endpoint or its mTLS alias
 * (PAR section 2: the server MUST accept any of them).
 *
 * upstream: condition/as/ValidateClientAssertionClaimsForPAREndpoint.java (validateAud)
 */
function validateParEndpointAud(c: Condition, assertion: ClientAssertion, server: ServerMetadata): void {
	const tokenEndpoint = serverString(server, "token_endpoint");
	const issuer = serverString(server, "issuer");
	const parEndpoint = serverString(server, "pushed_authorization_request_endpoint");
	const parMTLSEndpoint = mtlsAlias(server, "pushed_authorization_request_endpoint");
	const aud = assertion.claims["aud"];
	if (aud == null) {
		c.failure("Missing aud");
	}
	const expectedValues: (string | null)[] = [issuer, tokenEndpoint, parEndpoint];
	if (parMTLSEndpoint != null && parMTLSEndpoint !== "") {
		expectedValues.push(parMTLSEndpoint);
	}
	if (Array.isArray(aud)) {
		if (
			!(
				aud.includes(tokenEndpoint) ||
				aud.includes(issuer) ||
				aud.includes(parEndpoint) ||
				(parMTLSEndpoint != null && aud.includes(parMTLSEndpoint))
			)
		) {
			c.failure("aud values do not contain any of the expected values", { expected: expectedValues, actual: aud });
		}
	} else {
		const audStr = getString(aud);
		if (
			!(
				tokenEndpoint === audStr ||
				issuer === audStr ||
				parEndpoint === audStr ||
				(parMTLSEndpoint != null && parMTLSEndpoint === audStr)
			)
		) {
			c.failure("aud claim is not one of the expected values", { expected: expectedValues, actual: aud });
		}
	}
}

/**
 * iss and sub are the client_id, aud names this server, jti is present, nbf / exp / iat are plausible.
 *
 * upstream: condition/as/ValidateClientAssertionClaims.java
 * (`forParEndpoint`: condition/as/ValidateClientAssertionClaimsForPAREndpoint.java)
 */
export function validateClientAssertionClaims(
	assertion: ClientAssertion,
	client: RpClient,
	server: ServerMetadata,
	opts: { forParEndpoint?: boolean } = {},
	...requirements: string[]
): void {
	const c: Condition = condition(
		opts.forParEndpoint ? "ValidateClientAssertionClaimsForPAREndpoint" : "ValidateClientAssertionClaims",
		...requirements,
	);
	const now = Date.now(); // to check timestamps
	const clientId = client.client_id; // to check the client
	const issuer = serverString(server, "issuer"); // to validate the issuer
	// check all our testable values
	if (!clientId || !issuer) {
		c.failure(
			"Couldn't find issuer or client or token endpoint values in the test configuration to test the assertion",
		);
	}
	const claims = assertion.claims;
	if (claims["iss"] == null) {
		c.failure("Missing iss");
	}
	if (clientId !== getString(claims["iss"])) {
		c.failure("Issuer mismatch", { expected: clientId, actual: getString(claims["iss"]) });
	}
	if (opts.forParEndpoint) {
		validateParEndpointAud(c, assertion, server);
	} else {
		validateTokenEndpointAud(c, assertion, server);
	}
	if (claims["sub"] == null) {
		c.failure("Missing sub");
	}
	if (clientId !== getString(claims["sub"])) {
		c.failure("Subject mismatch", { expected: clientId, actual: getString(claims["sub"]) });
	}
	if (claims["jti"] == null) {
		c.failure("Missing JWT ID");
	}
	const nbf = long(claims, "nbf");
	if (nbf != null && now + TIME_SKEW_MILLIS < nbf * 1000) {
		// UPSTREAM: the stray quote is upstream's
		c.failure("Assertion 'nbf' value is in the future'", {
			"not-before": new Date(nbf * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	const exp = long(claims, "exp");
	if (exp == null) {
		c.failure("Missing exp");
	}
	if (now - TIME_SKEW_MILLIS > exp * 1000) {
		c.failure("Assertion expired", {
			expiration: new Date(exp * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	if (now + ONE_DAY_MILLIS < exp * 1000) {
		// Arbitrary, allow for 1 day in the future as standard says "unreasonably far".
		c.failure("Assertion expires unreasonable far in the future", {
			"expired-at": new Date(exp * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	const iat = long(claims, "iat");
	if (iat == null) {
		c.failure("Missing iat");
	}
	if (now + ONE_DAY_MILLIS < iat * 1000) {
		// UPSTREAM: the message and the logged exp are upstream's (an iat check)
		c.failure("Assertion expires unreasonable far in the future", {
			"issued-at": new Date(exp * 1000).toISOString(),
			now: new Date(now).toISOString(),
		});
	}
	c.success("Client Assertion passed all validation checks");
}

/**
 * `usedJtis`: the jti values presented so far (upstream: the environment of the test).
 *
 * upstream: condition/as/CheckForClientAssertionJtiReuse.java
 */
export function checkForClientAssertionJtiReuse(
	assertion: ClientAssertion,
	usedJtis: Set<string>,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckForClientAssertionJtiReuse", ...requirements);
	if (assertion.claims["jti"] == null) {
		c.failure("jti claim missing on client_assertion", { client_assertion: assertion });
	}
	const jti = getString(assertion.claims["jti"]);
	if (usedJtis.has(jti)) {
		c.failure("Detected reuse of client_assertion JWT for jti=" + jti, { client_assertion: assertion });
	}
	usedJtis.add(jti);
	c.success("No reuse found for client_assertion JWT for jti=" + jti);
}

/** FAPI 2.0 5.3.3.1-5: the aud is the issuer, as a string. upstream: condition/as/ValidateClientAssertionAudClaimIsIssuerAsString.java */
export function validateClientAssertionAudClaimIsIssuerAsString(
	assertion: ClientAssertion,
	issuer: string,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateClientAssertionAudClaimIsIssuerAsString", ...requirements);
	const aud = assertion.claims["aud"];
	if (aud == null) {
		c.failure("Missing aud not present in private_key_jwt client assertion");
	}
	if (Array.isArray(aud)) {
		c.failure("private_key_jwt aud claim is an array but should be a simple string", { expected: issuer, actual: aud });
	}
	if (issuer !== getString(aud)) {
		c.failure("private_key_jwt aud claim does not match the authentication server issuer url", {
			expected: issuer,
			actual: aud,
		});
	}
	c.success("private_key_jwt client Assertion 'aud' claim matches the authentication server issuer url");
}

/**
 * The private_key_jwt authentication of a token or PAR request: each check records its failure and the next one
 * runs (upstream callAndContinueOnFailure). Returns the assertion.
 *
 * upstream: sequence/as/ValidateClientAuthenticationWithPrivateKeyJWT.java with
 * condition/as/ExtractClientAssertion.java, EnsureClientAssertionSignatureAlgorithmMatchesRegistered.java,
 * ValidateClientAssertionSignature.java, EnsureClientAssertionTypeIsJwt.java, ValidateClientAssertionClaims.java,
 * ValidateClientAssertionClaimsForPAREndpoint.java, CheckForClientAssertionJtiReuse.java
 */
export async function validateClientAuthenticationWithPrivateKeyJWT(
	req: IncomingRequest,
	client: RpClient,
	server: ServerMetadata,
	usedJtis: Set<string>,
	opts: { forParEndpoint?: boolean } = {},
): Promise<ClientAssertion> {
	// UPSTREAM: callAndContinueOnFailure; the later conditions then fail one by one for the missing client_assertion
	// object ("Something unexpected happened ... couldn't find required object in environment") and the request is
	// still answered. Here the missing assertion ends the test with its failure.
	const assertion = extractClientAssertion(req, "RFC7523-2.2");
	soft(() => ensureClientAssertionSignatureAlgorithmMatchesRegistered(assertion, client, "OIDCR-2"));
	await soft(() => validateClientAssertionSignature(assertion, client, "OIDCC-9"));
	soft(() => ensureClientAssertionTypeIsJwt(req, "RFC7523-2.2"));
	if (opts.forParEndpoint) {
		soft(() => validateClientAssertionClaims(assertion, client, server, { forParEndpoint: true }, "PAR-2"));
	} else {
		soft(() => validateClientAssertionClaims(assertion, client, server, {}, "RFC7523-3", "OIDCC-9"));
	}
	soft(() => checkForClientAssertionJtiReuse(assertion, usedJtis, "RFC7523-3"));
	return assertion;
}
