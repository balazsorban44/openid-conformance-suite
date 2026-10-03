/**
 * JOSE for the suite: keys, JWK sets, signing and signature verification. Built on `jose`, with the Nimbus
 * emulation in src/util/nimbus (and the JWKUtil/JWTUtil/JWAUtil ports in src/util) wherever upstream's behaviour
 * and messages come from Nimbus (key parsing errors, key selection, JSON member order of logged keys).
 *
 * Functions that report through a check take the {@link Condition} they log under, so the entries keep the
 * upstream condition's name.
 */
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import type { Condition } from "./conditions.ts";
import { JWAUtil } from "../util/JWAUtil.ts";
import { JWKUtil, type JWK, type JWKSet } from "../util/JWKUtil.ts";
import { JWTUtil } from "../util/JWTUtil.ts";
import { EC_CURVE_ALGORITHM, keyTypeForAlgorithm } from "../util/nimbus/algorithms.ts";
import { isJOSEException, JOSEException, KeyLengthException, ParseException } from "../util/nimbus/errors.ts";
import { jwkSetToJSONObject } from "../util/nimbus/jwk.ts";
import { JWSSigner, selectJWSJwks, unsupportedJWSAlgorithm, verifySignedJWT } from "../util/nimbus/jws.ts";
import { parseClaimsSet, parseSignedJWT, type JWT } from "../util/nimbus/jwt.ts";

export type { JWK, JWKSet } from "../util/JWKUtil.ts";
/** A JWK set as JSON (Nimbus JWKSet in upstream) */
export type Jwks = JWKSet;

/** A parsed JWT as upstream stores it: the compact value, the header and the claims (JWTUtil) */
export interface ParsedJwt {
	value: string;
	header: Record<string, unknown>;
	claims: Record<string, unknown>;
	/** Only for an encrypted JWT that was decrypted */
	jwe_header?: Record<string, unknown>;
}

/**
 * A fresh RSA key pair as a private JWK with `use` and `alg` (upstream GenerateRS256ClientJWKs uses Nimbus'
 * RSAKey.Builder: no kid).
 */
export function generateRsaJwk(alg = "RS256", use = "sig", modulusLength = 2048): JWK {
	const { privateKey } = generateKeyPairSync("rsa", { modulusLength, publicExponent: 0x10001 });
	return { ...(privateKey as KeyObject).export({ format: "jwk" }), use, alg } as JWK;
}

/** The set with private members (Nimbus JWKSet.toJSONObject(false): Nimbus' member order) */
export function privateJwks(jwks: { keys: unknown[] }): Jwks {
	return jwkSetToJSONObject(jwks as never, false) as Jwks;
}

/** The set with only the public members (Nimbus JWKSet.toJSONObject(true)) */
export function publicJwks(jwks: { keys: unknown[] }): Jwks {
	return jwkSetToJSONObject(jwks as never, true) as Jwks;
}

/** Parses a compact JWT (decrypting it with the client's keys when it is a JWE), as JWTUtil does */
export async function parseJwt(
	token: string,
	client: Record<string, unknown> | null = null,
	privateJwksWithEncKeys: Record<string, unknown> | null = null,
): Promise<ParsedJwt> {
	return (await JWTUtil.jwtStringToJsonObjectForEnvironment(
		token,
		client as never,
		privateJwksWithEncKeys as never,
	)) as unknown as ParsedJwt;
}

/**
 * Parses a counterparty's JWK set leniently: keys the JOSE library cannot use are skipped and each is logged
 * (upstream AbstractLenientJwksCondition).
 */
export function parseJwksLenientlyLoggingSkips(c: Condition, jwks: unknown, jwksName: string): JWKSet {
	const skipped: { keyJson: unknown; reason: string }[] = [];
	const set = JWKUtil.parseJWKSetLeniently(JSON.stringify(jwks), skipped as never);
	for (const s of skipped) {
		c.log(
			"Ignoring a key in the " +
				jwksName +
				" JWKS that the JOSE library cannot parse (e.g. unsupported curve or key type)",
			{ key: s.keyJson, reason: s.reason },
		);
	}
	return set;
}

/**
 * Verifies a JWS against a JWK set and logs "<tokenName> signature validated" (upstream
 * AbstractVerifyJwsSignature.verifyJwsSignature, same key selection rules and messages).
 */
export async function verifyJwsSignature(
	c: Condition,
	token: string,
	jwks: unknown,
	tokenName: string,
	kidRequired: boolean,
	jwksName: string,
): Promise<void> {
	try {
		const jwt = parseSignedJWT(token);
		const jwkSet = parseJwksLenientlyLoggingSkips(c, jwks, jwksName);
		const header = jwt.header;
		const headerKeyID = typeof header["kid"] === "string" ? header["kid"] : null;
		const headerAlg = typeof header["alg"] === "string" ? header["alg"] : null;
		if (!JWAUtil.isJwsAlgorithm(headerAlg)) {
			c.failure(
				"The '" +
					tokenName +
					"' JWS header 'alg' is not a registered JWS signature or MAC algorithm, so its signature cannot be verified",
				{ alg: headerAlg, [tokenName]: token },
			);
		}
		const alg = headerAlg as string;
		const kty = keyTypeForAlgorithm(alg) as string;
		const x5tS256 = typeof header["x5t#S256"] === "string" ? header["x5t#S256"] : null;
		const details = { jwks, kid: headerKeyID, alg, kty, [tokenName]: token };

		let matching = 0;
		for (const k of jwkSet.keys) {
			if (
				headerKeyID != null &&
				headerKeyID === k["kid"] &&
				k["alg"] != null &&
				k["alg"] === alg &&
				k["use"] === "sig" &&
				k["kty"] === kty
			) {
				matching++;
				if (matching > 1) {
					c.failure(
						`Found more than one key in ${jwksName} JWKS that has the right kid, kty, alg and 'use':'sig'`,
						details,
					);
				}
			}
		}

		let verifiedWith: JWK | null = null;
		let candidate: JWK | null = null;
		if (headerKeyID) {
			for (const k of jwkSet.keys) {
				if (headerKeyID !== k["kid"] || !selectableForHeader(alg, kty, x5tS256, k)) {
					continue;
				}
				candidate = k;
				if (await verifyWithKey(jwt, k)) {
					verifiedWith = k;
					break;
				}
				c.failure(
					`Unable to verify ${tokenName} signature based on ${jwksName} key with the correct kid, kty that also matches (or does not have) alg/x5t#S256/'use':'sig'`,
					details,
				);
			}
			if (candidate == null) {
				c.failure(
					`${jwksName} JWKS does not contain a key with the correct kid, kty that also matches (or does not have) alg/x5t#S256/'use':'sig'`,
					details,
				);
			}
		} else {
			if (kidRequired) {
				c.failure("kid value in JWT header is missing/null/empty");
			}
			for (const k of jwkSet.keys) {
				if (!selectableForHeader(alg, kty, x5tS256, k)) {
					continue;
				}
				candidate = k;
				if (await verifyWithKey(jwt, k)) {
					verifiedWith = k;
					break;
				}
			}
			if (candidate == null) {
				c.failure(
					`${jwksName} JWKS does not contain a key with the correct kty that also matches (or does not have) alg/x5t#S256/'use':'sig'`,
					details,
				);
			}
			if (verifiedWith == null) {
				c.failure(`Unable to verify ${tokenName} signature based on ${jwksName} keys`, { jwks, [tokenName]: token });
			}
		}
		const publicKey = JWKUtil.toPublicJWK(verifiedWith as JWK);
		c.success(tokenName + " signature validated", {
			[tokenName]: { verifiable_jws: token, public_jwk: publicKey != null ? JSON.stringify(publicKey) : null },
		});
	} catch (e) {
		if (e instanceof JOSEException || e instanceof ParseException) {
			c.failureFrom("Error validating " + tokenName + " signature", e);
		}
		throw e;
	}
}

/** The key's kty matches, and alg / use / x5t#S256 match when the key has them */
function selectableForHeader(alg: string, kty: string, x5tS256: string | null, k: JWK): boolean {
	if (k["kty"] !== kty) {
		return false;
	}
	if (k["alg"] != null && alg !== k["alg"]) {
		return false;
	}
	if (k["use"] != null && k["use"] !== "sig") {
		return false;
	}
	// UPSTREAM: Java dereferences the key's x5t#S256 without a null check (NullPointerException); mirrored
	if (x5tS256 != null && x5tS256 !== (k["x5t#S256"] as unknown as { toString(): string }).toString()) {
		return false;
	}
	return true;
}

/** Nimbus DefaultJWSVerifierFactory + JWSVerifier.verify for one key (AbstractVerifyJwsSignature.verifySignature) */
async function verifyWithKey(jwt: JWT, jwk: JWK): Promise<boolean> {
	const alg = jwt.header["alg"] as string;
	for (const key of selectJWSJwks(jwt.header, { keys: [jwk] } as JWKSet)) {
		let verifier: Awaited<ReturnType<typeof JWKUtil.importKey>> | null = null;
		let verifierAlg = alg;
		try {
			if (key["kty"] === "OKP") {
				const publicKey = JWKUtil.parseJWK(JSON.stringify(JWKUtil.toPublicJWK(key)));
				if (publicKey["crv"] === "Ed25519") {
					verifier = await JWKUtil.importKey(publicKey, alg);
				}
			} else if (key["kty"] === "RSA" || key["kty"] === "EC") {
				const publicKey = JWKUtil.toPublicJWK(key) as JWK;
				if (publicKey["kty"] === "EC") {
					verifierAlg = EC_CURVE_ALGORITHM[publicKey["crv"] as string] ?? alg;
				}
				verifier = await JWKUtil.importKey(publicKey, verifierAlg);
			} else if (key["kty"] === "oct") {
				if (Buffer.from(String(key["k"]), "base64url").length < 256 / 8) {
					throw new KeyLengthException("The secret length must be at least 256 bits");
				}
				verifier = await JWKUtil.importKey(key, alg);
			}
		} catch {
			// the library could not build a verifier for this key (Java: catch (JOSEException | ParseException))
			verifier = null;
		}
		if (verifier != null) {
			if (verifierAlg !== alg) {
				throw new JOSEException(unsupportedJWSAlgorithm(alg, [verifierAlg]));
			}
			if (await verifySignedJWT(jwt, { jwk: key, key: verifier })) {
				return true;
			}
		}
	}
	return false;
}

/** The single signing key of a set (upstream AbstractGetSigningKey.getSigningKey) */
export function getSigningKey(c: Condition, name: string, jwks: unknown): JWK {
	let set: JWKSet;
	try {
		set = JWKUtil.parseJWKSet(JSON.stringify(jwks));
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Failed to parse " + name + " jwks", e);
		}
		throw e;
	}
	const signing = set.keys.filter((k) => k["use"] == null || k["use"] === "sig");
	if (signing.length === 0) {
		c.failure("Did not find a key with 'use': 'sig' or no 'use' claim, no key available to sign jwt", { jwks });
	}
	if (signing.length > 1) {
		c.failure(
			"Expected only one signing JWK in the set. Please ensure the signing key is the only one in the jwks, or that other keys have a 'use' other than 'sig'.",
			{ jwks },
		);
	}
	return signing[0];
}

/**
 * Signs `claims` with the single signing key of `jwks` (upstream AbstractSignJWT.signJWT without the x5c/x5t
 * options). Returns the JWS and the `{ verifiable_jws, public_jwk }` object upstream logs.
 */
export async function signJwt(
	c: Condition,
	claims: Record<string, unknown>,
	jwks: unknown,
	opts: { typ?: string } = {},
): Promise<{ jws: string; verifiable: { verifiable_jws: string; public_jwk: string | null } }> {
	try {
		const signingJwk = getSigningKey(c, "signing", jwks);
		if (signingJwk["alg"] == null) {
			c.failure("No 'alg' field specified in key; please add 'alg' field in the configuration", { jwk: signingJwk });
		}
		const alg = String(signingJwk["alg"]);
		const signer = JWSSigner.create(signingJwk, alg);
		const header: Record<string, unknown> = { alg };
		if (opts.typ) {
			header["typ"] = opts.typ;
		}
		if (signingJwk["kid"] != null) {
			header["kid"] = signingJwk["kid"];
		}
		const jws = await signer.sign(header as never, JSON.stringify(parseClaimsSet(claims as never)));
		const publicJwk = JWKUtil.toPublicJWK(signingJwk);
		return {
			jws,
			verifiable: { verifiable_jws: jws, public_jwk: publicJwk != null ? JSON.stringify(publicJwk) : null },
		};
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom(e.message, e);
		}
		if (isJOSEException(e)) {
			c.failureFrom(
				"Unable to sign client assertion; check provided key has correct 'kty' for it's 'alg': " +
					String(e.cause ?? null),
				e,
			);
		}
		throw e;
	}
}

/** Nimbus' JWK set parse (same ParseException messages) */
export function parseJwks(jwks: unknown): JWKSet {
	return JWKUtil.parseJWKSet(JSON.stringify(jwks));
}

export { ParseException, JOSEException } from "../util/nimbus/errors.ts";
