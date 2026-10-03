/**
 * The id_tokens the emulated OP issues: the signing algorithm it uses for the client, the claims (with at_hash /
 * c_hash / auth_time), signing, and the deliberate defects the negative RP tests put into them (wrong aud / iss /
 * nonce, no sub / iat, broken signature, alg none).
 */
import { createHash } from "node:crypto";
import { condition, ConditionFailed, skipped, type Condition } from "../suite/conditions.ts";
import type { Jwks } from "../suite/jose.ts";
import { InvalidAlgorithmException, JWAUtil } from "../util/JWAUtil.ts";
import {
	JWKUtil,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	type JWK,
} from "../util/JWKUtil.ts";
import { JWTUtil } from "../util/JWTUtil.ts";
import { toUsAscii } from "../util/jdk/strings.ts";
import { isJOSEException, ParseException } from "../util/nimbus/errors.ts";
import { JWSSigner } from "../util/nimbus/jws.ts";
import { parseClaimsSet } from "../util/nimbus/jwt.ts";
import type { EmulatedOp } from "./op.ts";
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
		keys = JWKUtil.parseJWKSet(JSON.stringify(serverJwks)).keys;
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
		digestAlgorithm = JWAUtil.getDigestAlgorithmForSigAlg(algorithm);
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
		jwk = JWKUtil.parseJWK({
			kty: "oct",
			use: "sig",
			alg,
			k: Buffer.from(client["client_secret"]).toString("base64url"),
		});
	} else {
		try {
			jwk = JWKUtil.selectAsymmetricJWSKey(alg, JWKUtil.parseJWKSet(JSON.stringify(serverJwks)).keys);
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
				? JWSSigner.rsa(jwk)
				: kty === "EC"
					? JWSSigner.ec(jwk)
					: kty === "oct"
						? JWSSigner.mac(jwk)
						: kty === "OKP"
							? JWSSigner.ed25519(jwk)
							: null;
		if (signer == null) {
			c.failure("Couldn't create signer from key; kty must be one of 'oct', 'rsa', 'ec'", { jwk: JSON.stringify(jwk) });
		}
		const header: Record<string, unknown> = { alg };
		if (jwk["kid"] != null) {
			header["kid"] = jwk["kid"];
		}
		const jws = await signer.sign(header as never, JSON.stringify(parseClaimsSet(claims as never)));
		const publicJwk = JWKUtil.toPublicJWK(jwk);
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
		const jwt = JWTUtil.parseJWT(idToken);
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
 * changes to them (`idTokenClaims`), at_hash / c_hash, auth_time when max_age was requested, signed
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
	if (!codeGrant && authz?.cHash == null) {
		skipped("AddCHashToIdTokenClaims", { string: "c_hash" }, "OIDCC-3.3.2.11");
	} else if (!codeGrant) {
		addCHashToIdTokenClaims(claims, authz?.cHash as string, "OIDCC-3.3.2.11");
	}
	if (op.tokens?.atHash == null) {
		skipped("AddAtHashToIdTokenClaims", { string: "at_hash" }, "OIDCC-3.3.2.11");
	} else {
		addAtHashToIdTokenClaims(claims, op.tokens.atHash, "OIDCC-3.3.2.11");
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
	let idToken = op.options.signIdToken
		? await op.options.signIdToken(claims, op)
		: await oidccSignIdToken(claims, op.keys.jwks, client, op.signingAlg as string, "OIDCC-2");
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
