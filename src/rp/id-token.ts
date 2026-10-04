/**
 * The id_tokens the emulated OP issues: the signing algorithm it uses for the client, the claims (with at_hash /
 * c_hash / auth_time), signing, and the deliberate defects the negative RP tests put into them (wrong aud / iss /
 * nonce, no sub / iat, broken signature, alg none).
 */
import { createHash } from "node:crypto";
import { condition, ConditionFailed, skipped, type Condition } from "../suite/conditions.ts";
import type { Jwks } from "../suite/jose.ts";
import {
	InvalidAlgorithmException,
	getDigestAlgorithmForSigAlg,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
} from "../suite/jose-algorithms.ts";
import { parseJWKSet, parseJWK, selectAsymmetricJWSKey, toPublicJWK, type JWK } from "../suite/jose-jwk.ts";
import { parseJWT, parseClaimsSet } from "../suite/jose-jwt.ts";
import { isJOSEException, ParseException } from "../suite/errors.ts";
import { rsaSigner, ecSigner, macSigner, ed25519Signer } from "../suite/jose-jws.ts";
import type { EmulatedOp, RefreshOptions } from "./op.ts";
import type { RpClient } from "./registration.ts";
import type { UserInfo } from "./userinfo.ts";

/** upstream env "id_token_claims" */
export type IdTokenClaims = Record<string, unknown>;

// ---------------------------------------------------------------------------------------------------------------
// the signing algorithm

/** True unless the client only uses the code response type (AbstractClientValidationCondition.hasImplicitResponseTypes) */
function hasImplicitResponseTypes(client: Record<string, unknown>): boolean {
	const types = Array.isArray(client["response_types"]) ? client["response_types"] : ["code"];
	return !(types.length === 1 && types[0] === "code");
}

/** The algorithm a key type signs with by default (OIDCCExtractServerSigningAlg.getDefaultAlgForKeyType) */
function defaultAlgForKeyType(c: Condition, keyType: string): string {
	const alg = { RSA: "RS256", EC: "ES256", OKP: "EdDSA", oct: "HS256" }[keyType];
	if (alg == null) {
		c.failure("Unexpected key type", { key_type: keyType });
	}
	return alg;
}

/**
 * The id_token signing algorithm for the client: its id_token_signed_response_alg if the OP has a suitable key
 * (none and HS* need none), else the algorithm of the first signing key.
 *
 * upstream: condition/as/OIDCCExtractServerSigningAlg.java
 */
export function oidccExtractServerSigningAlg(client: RpClient, serverJwks: Jwks): string {
	const c: Condition = condition("OIDCCExtractServerSigningAlg");
	const configuredAlg =
		typeof client["id_token_signed_response_alg"] === "string" ? client["id_token_signed_response_alg"] : null;
	let keys: JWK[];
	try {
		keys = parseJWKSet(JSON.stringify(serverJwks)).keys;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom(configuredAlg == null ? "Failed to parse server_jwks" : "Could not parse server jwks.", e, {
				server_jwks: serverJwks,
			});
		}
		throw e;
	}
	if (configuredAlg == null) {
		for (const jwk of keys) {
			if (jwk["use"] != null && jwk["use"] !== "sig") {
				continue;
			}
			if (jwk["alg"] == null) {
				const alg = defaultAlgForKeyType(c, String(jwk["kty"]));
				c.success("Using the default algorithm for the first key in server jwks", { signing_algorithm: alg });
				return alg;
			}
			c.success("Using the algorithm for the first key in server jwks", { signing_algorithm: jwk["alg"] });
			return String(jwk["alg"]);
		}
		c.failure("Failed to find a suitable signing key in server jwks", { server_jwks: serverJwks });
	}
	if (configuredAlg === "none") {
		if (hasImplicitResponseTypes(client)) {
			c.failure("none algorithm can only be used when only 'code' response type will be used");
		}
		c.success("Using client id_token_signed_response_alg, which is 'none', as the signing algorithm", {
			signing_algorithm: configuredAlg,
		});
		return "none";
	}
	if (configuredAlg.startsWith("HS")) {
		if (!JWS_FAMILY_HMAC_SHA.includes(configuredAlg)) {
			c.failure("Unexpected algorithm", { alg: configuredAlg });
		}
		c.success("Using client id_token_signed_response_alg as the signing algorithm", {
			signing_algorithm: configuredAlg,
		});
		return configuredAlg;
	}
	const keyType = JWS_FAMILY_RSA.includes(configuredAlg)
		? "RSA"
		: JWS_FAMILY_EC.includes(configuredAlg)
			? "EC"
			: JWS_FAMILY_ED.includes(configuredAlg)
				? "OKP"
				: null;
	let foundAlg: string | null = null;
	for (const key of keys) {
		if (key["kty"] === keyType && (key["use"] == null || key["use"] === "sig")) {
			if (key["alg"] == null) {
				// there may be a more specific match later so don't break
				foundAlg = configuredAlg;
			} else if (key["alg"] === configuredAlg) {
				foundAlg = configuredAlg;
				break;
			}
		}
	}
	if (foundAlg == null) {
		c.failure("Could not find a suitable key in server_jwks for client id_token_signed_response_alg.", {
			server_jwks: serverJwks,
			id_token_signed_response_alg: configuredAlg,
		});
	}
	c.success("Selected signing algorithm based on client id_token_signed_response_alg.", {
		selected_algorithm: foundAlg,
		id_token_signed_response_alg: configuredAlg,
	});
	return foundAlg;
}

/** upstream: condition/as/SetServerSigningAlgToRS256.java */
export function setServerSigningAlgToRS256(...requirements: string[]): string {
	condition("SetServerSigningAlgToRS256", ...requirements).log("Successfully set signing algorithm to RS256");
	return "RS256";
}

/** upstream: condition/as/SetServerSigningAlgToNone.java */
export function setServerSigningAlgToNone(...requirements: string[]): string {
	condition("SetServerSigningAlgToNone", ...requirements).log("Successfully set signing algorithm to none", {
		signing_algorithm: "none",
	});
	return "none";
}

// ---------------------------------------------------------------------------------------------------------------
// claims

/** upstream: condition/as/GenerateIdTokenClaims.java */
export function generateIdTokenClaims(
	userInfo: UserInfo,
	issuer: string,
	clientId: string | undefined,
	nonce: string | null,
): IdTokenClaims {
	const c: Condition = condition("GenerateIdTokenClaims");
	const subject = typeof userInfo["sub"] === "string" ? userInfo["sub"] : null;
	if (!subject) {
		c.failure("Couldn't find subject");
	}
	if (!issuer) {
		c.failure("Couldn't find issuer");
	}
	if (!clientId) {
		c.failure("Couldn't find client ID");
	}
	const claims: IdTokenClaims = { iss: issuer, sub: subject, aud: clientId };
	if (nonce) {
		claims["nonce"] = nonce;
	}
	const iat = Math.floor(Date.now() / 1000);
	claims["iat"] = iat;
	claims["exp"] = iat + 5 * 60;
	c.success("Created ID Token Claims", claims);
	return claims;
}

/**
 * The left half of the hash of `value` with the digest of the signing algorithm, base64url (OIDC at_hash / c_hash).
 *
 * The shared body of CalculateAtHash and CalculateCHash.
 */
function halfHash(name: string, hashName: string, value: string, algorithm: string, requirements: string[]): string {
	const c: Condition = condition(name, ...requirements);
	let digestAlgorithm: string;
	try {
		digestAlgorithm = getDigestAlgorithmForSigAlg(algorithm);
	} catch (e) {
		if (e instanceof InvalidAlgorithmException) {
			c.failureFrom("Unsupported algorithm", e, { alg: algorithm });
		}
		throw e;
	}
	const digest = createHash(digestAlgorithm.replace("-", "").toLowerCase())
		.update(Buffer.from(toUsAscii(value), "latin1"))
		.digest();
	const hash = digest.subarray(0, Math.floor(digest.length / 2)).toString("base64url");
	c.success(`Successful ${hashName} encoding`, { [hashName]: hash });
	return hash;
}

/** Java String.getBytes(US_ASCII): every non-ASCII character (code point) becomes '?' */
export function toUsAscii(s: string): string {
	return Array.from(s, (c) => ((c.codePointAt(0) as number) > 0x7f ? "?" : c)).join("");
}

/** upstream: condition/as/CalculateAtHash.java */
export function calculateAtHash(accessToken: string, signingAlg: string, ...requirements: string[]): string {
	return halfHash("CalculateAtHash", "at_hash", accessToken, signingAlg, requirements);
}

/** upstream: condition/as/CalculateCHash.java */
export function calculateCHash(code: string, signingAlg: string, ...requirements: string[]): string {
	return halfHash("CalculateCHash", "c_hash", code, signingAlg, requirements);
}

/** upstream: condition/as/AddAtHashToIdTokenClaims.java */
export function addAtHashToIdTokenClaims(claims: IdTokenClaims, atHash: string, ...requirements: string[]): void {
	claims["at_hash"] = atHash;
	condition("AddAtHashToIdTokenClaims", ...requirements).success("Added at_hash to ID token claims", {
		id_token_claims: claims,
		at_hash: atHash,
	});
}

/** upstream: condition/as/AddCHashToIdTokenClaims.java */
export function addCHashToIdTokenClaims(claims: IdTokenClaims, cHash: string, ...requirements: string[]): void {
	claims["c_hash"] = cHash;
	condition("AddCHashToIdTokenClaims", ...requirements).success("Added c_hash to ID token claims", {
		id_token_claims: claims,
		c_hash: cHash,
	});
}

/** upstream: condition/as/AddAuthTimeToIdTokenClaims.java */
export function addAuthTimeToIdTokenClaims(claims: IdTokenClaims, authTime: number, ...requirements: string[]): void {
	claims["auth_time"] = authTime;
	condition("AddAuthTimeToIdTokenClaims", ...requirements).success("Added auth_time to ID token claims", {
		id_token_claims: claims,
		auth_time: String(authTime),
	});
}

/** upstream: condition/as/AddUserinfoClaimsToIdTokenClaims.java */
export function addUserinfoClaimsToIdTokenClaims(
	claims: IdTokenClaims,
	userinfo: UserInfo,
	...requirements: string[]
): void {
	Object.assign(claims, userinfo);
	condition("AddUserinfoClaimsToIdTokenClaims", ...requirements).log(
		"Added userinfo claims to ID Token Claims",
		claims,
	);
}

/** upstream: condition/as/AddInvalidAudValueToIdToken.java */
export function addInvalidAudValueToIdToken(claims: IdTokenClaims, ...requirements: string[]): void {
	const aud = `${String(claims["aud"])}1`;
	claims["aud"] = aud;
	condition("AddInvalidAudValueToIdToken", ...requirements).success("Added invalid aud to ID token claims", {
		id_token_claims: claims,
		aud,
	});
}

/** upstream: condition/as/AddInvalidIssValueToIdToken.java */
export function addInvalidIssValueToIdToken(claims: IdTokenClaims, ...requirements: string[]): void {
	const iss = `${String(claims["iss"])}1`;
	claims["iss"] = iss;
	condition("AddInvalidIssValueToIdToken", ...requirements).success("Added invalid iss to ID token claims", {
		id_token_claims: claims,
		iss,
	});
}

/** upstream: condition/as/AddInvalidSubValueToIdToken.java */
export function addInvalidSubValueToIdToken(claims: IdTokenClaims, ...requirements: string[]): void {
	const sub = `${String(claims["sub"])}1`;
	claims["sub"] = sub;
	condition("AddInvalidSubValueToIdToken", ...requirements).log("Added invalid sub to ID token claims", {
		id_token_claims: claims,
		sub,
	});
}

/** upstream: condition/as/AddInvalidNonceValueToIdToken.java */
export function addInvalidNonceValueToIdToken(claims: IdTokenClaims, ...requirements: string[]): void {
	// UPSTREAM: a missing nonce becomes "null1"
	const nonce = `${claims["nonce"] == null ? "null" : String(claims["nonce"])}1`;
	claims["nonce"] = nonce;
	condition("AddInvalidNonceValueToIdToken", ...requirements).success("Added invalid nonce to ID token claims", {
		id_token_claims: claims,
		nonce,
	});
}

/** upstream: condition/as/RemoveSubFromIdToken.java */
export function removeSubFromIdToken(claims: IdTokenClaims, ...requirements: string[]): void {
	delete claims["sub"];
	condition("RemoveSubFromIdToken", ...requirements).log("Removed sub value from ID token claims", {
		id_token_claims: claims,
	});
}

/** upstream: condition/as/RemoveIatFromIdToken.java */
export function removeIatFromIdToken(claims: IdTokenClaims, ...requirements: string[]): void {
	delete claims["iat"];
	condition("RemoveIatFromIdToken", ...requirements).success("Removed iat from ID token claims", {
		id_token_claims: claims,
	});
}

/** upstream: condition/as/AddInvalidAtHashValueToIdToken.java */
export function addInvalidAtHashValueToIdToken(
	claims: IdTokenClaims,
	atHash: string | null,
	...requirements: string[]
): void {
	if (atHash == null) {
		// UPSTREAM: @PreEnvironment(strings = "at_hash"): the framework stops the test before the condition runs
		throw new Error("AddInvalidAtHashValueToIdToken: no at_hash was calculated (no access token was issued)");
	}
	// add number 1 onto end of at_hash string
	const concat = atHash + "1";
	claims["at_hash"] = concat;
	condition("AddInvalidAtHashValueToIdToken", ...requirements).success("Added invalid at_hash to ID token claims", {
		id_token_claims: claims,
		invalid_at_hash: concat,
	});
}

/** upstream: condition/as/AddInvalidCHashValueToIdToken.java */
export function addInvalidCHashValueToIdToken(
	claims: IdTokenClaims,
	cHash: string | null,
	...requirements: string[]
): void {
	if (cHash == null) {
		// UPSTREAM: @PreEnvironment(strings = "c_hash"): the framework stops the test before the condition runs
		throw new Error("AddInvalidCHashValueToIdToken: no c_hash was calculated (no authorization code was issued)");
	}
	// add number 1 onto end of hash string
	const concat = cHash + "1";
	claims["c_hash"] = concat;
	condition("AddInvalidCHashValueToIdToken", ...requirements).success("Added invalid c_hash to ID token claims", {
		id_token_claims: claims,
		c_hash: concat,
	});
}

/**
 * at_hash in the id_token when an access token was issued with it (skipped otherwise); the step a module replaces
 * with its `addAtHashToIdToken` option.
 *
 * upstream: AbstractOIDCCClientTest.addAtHashToIdToken
 */
export function addAtHashToIdToken(claims: IdTokenClaims, atHash: string | null): void {
	if (atHash == null) {
		skipped("AddAtHashToIdTokenClaims", { string: "at_hash" }, "OIDCC-3.3.2.11");
	} else {
		addAtHashToIdTokenClaims(claims, atHash, "OIDCC-3.3.2.11");
	}
}

/**
 * c_hash in an id_token from the authorization endpoint when a code was issued with it (skipped otherwise); the
 * step a module replaces with its `addCHashToIdToken` option.
 *
 * upstream: AbstractOIDCCClientTest.addCHashToIdToken
 */
export function addCHashToIdToken(claims: IdTokenClaims, cHash: string | null): void {
	if (cHash == null) {
		skipped("AddCHashToIdTokenClaims", { string: "c_hash" }, "OIDCC-3.3.2.11");
	} else {
		addCHashToIdTokenClaims(claims, cHash, "OIDCC-3.3.2.11");
	}
}

// ---------------------------------------------------------------------------------------------------------------
// signing

const ALG_NONE_HEADER = Buffer.from('{"alg":"none"}').toString("base64url");

/**
 * Signs the id_token with the key the OP has for the algorithm (an HMAC key from the client secret for HS*), or
 * not at all for alg none.
 *
 * upstream: condition/as/OIDCCSignIdToken.java (AbstractSignJWT.selectOrCreateKey, signJWTUsingKey, signWithAlgNone)
 */
export async function oidccSignIdToken(
	claims: IdTokenClaims,
	serverJwks: Jwks,
	client: RpClient,
	signingAlgorithm: string,
	...requirements: string[]
): Promise<string> {
	const c: Condition = condition("OIDCCSignIdToken", ...requirements);
	const configured = client["id_token_signed_response_alg"];
	const alg = typeof configured === "string" && configured.length > 0 ? configured : signingAlgorithm;
	if (alg === "none") {
		const jws = ALG_NONE_HEADER + "." + Buffer.from(JSON.stringify(claims)).toString("base64url") + ".";
		c.success("Signed the ID token", { id_token: jws, algorithm: "none", key: "none" });
		return jws;
	}
	let jwk: JWK | null;
	if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		// a MAC based alg: the key is the client secret
		if (typeof client["client_secret"] !== "string") {
			throw new Error("getString called on something that is not a string: " + JSON.stringify(client["client_secret"]));
		}
		jwk = parseJWK({
			kty: "oct",
			use: "sig",
			alg,
			k: Buffer.from(client["client_secret"]).toString("base64url"),
		});
	} else {
		try {
			jwk = selectAsymmetricJWSKey(alg, parseJWKSet(JSON.stringify(serverJwks)).keys);
		} catch (e) {
			if (e instanceof ParseException) {
				c.failureFrom("Could not parse jwks. Failed to find a signing key.", e, { jwks: serverJwks, alg });
			}
			throw e;
		}
		if (jwk == null) {
			c.failure("Jwks does not contain a suitable signing key for the selected algorithm", { signing_algorithm: alg });
		}
	}
	try {
		const kty = jwk["kty"];
		const signer =
			kty === "RSA"
				? rsaSigner(jwk)
				: kty === "EC"
					? ecSigner(jwk)
					: kty === "oct"
						? macSigner(jwk)
						: kty === "OKP"
							? ed25519Signer(jwk)
							: null;
		if (signer == null) {
			c.failure("Couldn't create signer from key; kty must be one of 'oct', 'rsa', 'ec'", { jwk: JSON.stringify(jwk) });
		}
		const header: Record<string, unknown> = { alg };
		if (jwk["kid"] != null) {
			header["kid"] = jwk["kid"];
		}
		const jws = await signer.sign(header as never, JSON.stringify(parseClaimsSet(claims as never)));
		const publicJwk = toPublicJWK(jwk);
		c.success("Signed the ID token", {
			id_token: { verifiable_jws: jws, public_jwk: publicJwk != null ? JSON.stringify(publicJwk) : null },
			algorithm: alg,
			key: JSON.stringify(jwk),
		});
		return jws;
	} catch (e) {
		if (e instanceof ConditionFailed) {
			throw e;
		}
		if (e instanceof ParseException) {
			c.failureFrom(e.message, e);
		}
		if (isJOSEException(e)) {
			const cause = (e as Error).cause;
			c.failureFrom(
				"Unable to sign: " + (e as Error).message + (cause instanceof Error ? " (" + cause.message + ")" : ""),
				e,
			);
		}
		throw e;
	}
}

/** upstream: condition/as/SignIdTokenWithAlgNone.java */
export function signIdTokenWithAlgNone(claims: IdTokenClaims, ...requirements: string[]): string {
	const jwt = ALG_NONE_HEADER + "." + Buffer.from(JSON.stringify(claims), "utf8").toString("base64url") + ".";
	condition("SignIdTokenWithAlgNone", ...requirements).success("Created id_token with alg none", { id_token: jwt });
	return jwt;
}

/**
 * Flips bits of the signature so that it no longer verifies.
 *
 * upstream: condition/as/InvalidateIdTokenSignature.java (AbstractInvalidateJwsSignature)
 */
export function invalidateIdTokenSignature(idToken: string, ...requirements: string[]): string {
	const c: Condition = condition("InvalidateIdTokenSignature", ...requirements);
	let invalid: string;
	try {
		const jwt = parseJWT(idToken);
		if (jwt.type !== "signed") {
			throw new ParseException("Not a JWS header");
		}
		const bytes = Buffer.from(jwt.signature as string, "base64url");
		for (let i = 0; i < bytes.length; i++) {
			bytes[i] ^= 0x5a;
		}
		invalid = jwt.parts[0] + "." + jwt.parts[1] + "." + bytes.toString("base64url");
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse JWT", e, { id_token: idToken });
		}
		throw e;
	}
	c.log("Made the id_token signature invalid", { id_token: invalid });
	return invalid;
}

// ---------------------------------------------------------------------------------------------------------------
// the id_token of a response

/**
 * Creates the id_token for the token endpoint (`codeGrant`) or the authorization endpoint: the claims, the module's
 * changes to them (`idTokenClaims`), c_hash (authorization endpoint only) and at_hash (or the module's
 * `addCHashToIdToken` / `addAtHashToIdToken` in their place), auth_time when max_age was requested, signed
 * (`signIdToken`, default OIDCCSignIdToken) and the module's change to the signature (`idTokenSignature`).
 * Encrypted id_tokens are not supported yet.
 *
 * upstream: AbstractOIDCCClientTest.createIdToken
 */
export async function createIdToken(op: EmulatedOp, codeGrant: boolean): Promise<string> {
	const client = op.client as RpClient;
	const authz = op.authorization;
	const claims = generateIdTokenClaims(op.userInfo, op.issuer, client.client_id, authz?.nonce ?? null);
	op.options.idTokenClaims?.(claims, op);
	if (!codeGrant) {
		const cHash = authz?.cHash ?? null;
		if (op.options.addCHashToIdToken) {
			op.options.addCHashToIdToken(claims, cHash);
		} else {
			addCHashToIdToken(claims, cHash);
		}
	}
	const atHash = op.tokens?.atHash ?? null;
	if (op.options.addAtHashToIdToken) {
		op.options.addAtHashToIdToken(claims, atHash);
	} else {
		addAtHashToIdToken(claims, atHash);
	}
	if (codeGrant || op.responseType.includesIdToken) {
		if (authz?.params["max_age"] == null) {
			skipped(
				"AddAuthTimeToIdTokenClaims",
				{ element: ["effective_authorization_endpoint_request", "max_age"] },
				"OIDCC-3.1.2.1",
			);
		} else {
			addAuthTimeToIdTokenClaims(claims, authz.authTime ?? Math.floor(Date.now() / 1000), "OIDCC-3.1.2.1");
		}
	}
	op.options.customIdTokenClaims?.(claims, op);
	let idToken = op.options.signIdToken
		? await op.options.signIdToken(claims, op)
		: await oidccSignIdToken(claims, op.keys.jwks, client, op.signingAlg as string, "OIDCC-2");
	if (!op.options.signIdToken) {
		// upstream OIDCCSignIdToken records every id_token it signs ("all_issued_id_tokens")
		op.issuedIdTokens.push(idToken);
	}
	if (op.options.idTokenSignature) {
		idToken = op.options.idTokenSignature(idToken);
	}
	if (client["id_token_encrypted_response_alg"] == null) {
		skipped("EncryptIdToken", { element: ["client", "id_token_encrypted_response_alg"] }, "OIDCC-10.2");
	} else {
		throw new Error("TODO(port): encrypted id_tokens (EncryptIdToken)");
	}
	return idToken;
}

/**
 * The id_token of a refresh response: the claims (no auth_time), at_hash, the module's changes
 * (`customIdTokenClaims`), signed with OIDCCSignIdToken and changed by `idTokenSignature`.
 *
 * upstream: AbstractOIDCCClientTestRefreshToken.createIdTokenForRefreshRequest
 */
export async function createIdTokenForRefreshRequest(op: EmulatedOp, refresh: RefreshOptions): Promise<string> {
	const client = op.client as RpClient;
	const claims = generateIdTokenClaims(op.userInfo, op.issuer, client.client_id, op.authorization?.nonce ?? null);
	addAtHashToIdToken(claims, op.tokens?.atHash ?? null);
	refresh.customIdTokenClaims?.(claims, op);
	let idToken = await oidccSignIdToken(claims, op.keys.jwks, client, op.signingAlg as string, "OIDCC-2");
	op.issuedIdTokens.push(idToken);
	if (refresh.idTokenSignature) {
		idToken = refresh.idTokenSignature(idToken);
	}
	if (client["id_token_encrypted_response_alg"] == null) {
		skipped("EncryptIdToken", { element: ["client", "id_token_encrypted_response_alg"] }, "OIDCC-10.2");
	} else {
		throw new Error("TODO(port): encrypted id_tokens (EncryptIdToken)");
	}
	return idToken;
}
