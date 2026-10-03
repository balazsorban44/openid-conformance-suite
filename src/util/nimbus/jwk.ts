/**
 * Nimbus `com.nimbusds.jose.jwk`: JWK / JWK set parsing and serialization (`JWK.parse`, `JWKSet.parse`,
 * `toJSONObject`, `toPublicJWK`, `isPrivate`, `getRequiredParams`), `JWKMatcher.forJWSHeader`, and the bridge from a
 * JSON JWK to a jose key (what Nimbus' `toRSAPublicKey()`, `toECPrivateKey()`, `toSecretKey()` ... are used for).
 *
 * The JSON form produced here has the same members, in the same order, as Nimbus' `toJSONObject()`: members Nimbus
 * does not know are dropped, as they are when Java round-trips via Nimbus.
 *
 * Not lock-tracked: there is no upstream Java file for this module.
 */
import { createHash, createPublicKey, X509Certificate } from "node:crypto";
import { importJWK, type CryptoKey, type JWK as JoseJWK } from "jose";
import { isJsonArray, isJsonObject, type JsonArray, type JsonObject, type JsonValue } from "../../framework/json.ts";
import {
	curvesForJWSAlgorithm,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	keyTypeForAlgorithm,
} from "./algorithms.ts";
import { ParseException } from "./errors.ts";
import { JavaHashMap } from "./HashMap.ts";
import {
	nimbusGetJSONArray,
	nimbusGetJSONObject,
	nimbusGetLong,
	nimbusGetString,
	nimbusGetStringList,
	nimbusGetURI,
	nimbusParseJsonObject,
} from "./json.ts";

/**
 * A JSON Web Key as plain JSON. Replaces Nimbus `com.nimbusds.jose.jwk.JWK` (and its subclasses `RSAKey`,
 * `ECKey`, `OctetKeyPair`, `OctetSequenceKey`). It is both a {@link JsonObject} (so it can be stored in the
 * environment as is) and a jose `JWK` (so it can be passed to `importJWK`).
 */
export type JWK = JsonObject & JoseJWK;

/** A JSON Web Key set as plain JSON. Replaces Nimbus `com.nimbusds.jose.jwk.JWKSet`. */
export type JWKSet = JsonObject & { keys: JWK[] };

/** Curves Nimbus `ECKey` supports */
export const EC_SUPPORTED_CURVES: readonly string[] = ["P-256", "secp256k1", "P-384", "P-521"];
/** Curves Nimbus `OctetKeyPair` supports */
export const OKP_SUPPORTED_CURVES: readonly string[] = ["Ed25519", "Ed448", "X25519", "X448"];
const KEY_OPERATIONS = ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"];
const KEY_USE_OPS: Record<string, string[]> = {
	sig: ["sign", "verify"],
	enc: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
};

/** Nimbus Curve.parse */
export function parseCurve(s: string | null): string {
	if (s == null || s.trim().length === 0) {
		throw new Error("The cryptographic curve string must not be null or empty");
	}
	return s;
}

/** Big-endian unsigned integer comparison of two base64url values (Base64URL.decodeToBigInteger().equals) */
function sameBigInteger(a: string, b: string): boolean {
	const strip = (buf: Buffer) => {
		let i = 0;
		while (i < buf.length - 1 && buf[i] === 0) {
			i++;
		}
		return buf.subarray(i).toString("hex");
	};
	return strip(Buffer.from(a, "base64url")) === strip(Buffer.from(b, "base64url"));
}

/**
 * Port of `com.nimbusds.jose.jwk.JWK.parse(Map)`: validates the key the way Nimbus does (same error messages) and
 * returns the JSON produced by Nimbus' `toJSONObject()` for it.
 */
function parseJWKObject(o: JsonObject): JWK {
	const kty = nimbusGetString(o, "kty");
	if (kty == null) {
		throw new ParseException('Missing key type "kty" parameter');
	}
	if (kty !== "EC" && kty !== "RSA" && kty !== "oct" && kty !== "OKP") {
		throw new ParseException('Unsupported key type "kty" parameter: ' + kty);
	}

	// type specific parameters, read before the metadata as in the Nimbus parse methods
	let crv: string | null = null;
	const params: Record<string, string | null> = {};
	let oth: JsonArray | null = null;
	try {
		if (kty === "EC" || kty === "OKP") {
			crv = parseCurve(nimbusGetString(o, "crv"));
		}
	} catch (e) {
		if (e instanceof ParseException) {
			throw e;
		}
		throw new ParseException((e as Error).message);
	}
	const typeParams: Record<string, string[]> = {
		EC: ["x", "y", "d"],
		OKP: ["x", "d"],
		RSA: ["n", "e", "d", "p", "q", "dp", "dq", "qi"],
		oct: ["k"],
	};
	for (const p of typeParams[kty]) {
		params[p] = nimbusGetString(o, p);
	}
	if (kty === "RSA" && "oth" in o) {
		oth = nimbusGetJSONArray(o, "oth");
		if (oth != null) {
			for (const item of oth) {
				if (isJsonObject(item)) {
					for (const m of ["r", "d", "t"]) {
						if (nimbusGetString(item, m) == null) {
							throw new ParseException("The " + m + " value must not be null");
						}
					}
				}
			}
		}
	}

	// metadata (JWKMetadata.parse*)
	const use = nimbusGetString(o, "use");
	if (use != null && use !== "sig" && use !== "enc" && use.trim().length === 0) {
		throw new ParseException("JWK use value must not be empty or blank");
	}
	let ops: string[] | null = null;
	const opsList = nimbusGetStringList(o, "key_ops");
	if (opsList != null) {
		ops = [];
		for (const s of opsList) {
			if (s == null) {
				continue;
			}
			if (!KEY_OPERATIONS.includes(s)) {
				throw new ParseException("Invalid JWK operation: " + s);
			}
			if (!ops.includes(s)) {
				ops.push(s);
			}
		}
	}
	const alg = nimbusGetString(o, "alg");
	const kid = nimbusGetString(o, "kid");
	const x5u = nimbusGetURI(o, "x5u");
	const x5t = nimbusGetString(o, "x5t");
	const x5t256 = nimbusGetString(o, "x5t#S256");
	let x5c: string[] | null = null;
	const x5cArr = nimbusGetJSONArray(o, "x5c");
	if (x5cArr != null) {
		x5c = [];
		for (let i = 0; i < x5cArr.length; i++) {
			const item = x5cArr[i];
			if (item == null) {
				throw new ParseException("The X.509 certificate at position " + i + " must not be null");
			}
			if (typeof item !== "string") {
				throw new ParseException("The X.509 certificate at position " + i + " must be encoded as a Base64 string");
			}
			x5c.push(item);
		}
		if (x5c.length === 0) {
			x5c = null; // Empty chains not allowed
		}
	}
	const exp = o["exp"] == null ? null : nimbusGetLong(o, "exp");
	const nbf = o["nbf"] == null ? null : nimbusGetLong(o, "nbf");
	const iat = o["iat"] == null ? null : nimbusGetLong(o, "iat");
	let revoked: JsonObject | null = null;
	if (o["revoked"] != null) {
		revoked = nimbusGetJSONObject(o, "revoked") as JsonObject;
		const revokedOut: JsonObject = { revoked_at: nimbusGetLong(revoked, "revoked_at") };
		if (revoked["reason"] != null) {
			revokedOut["reason"] = nimbusGetString(revoked, "reason");
		}
		revoked = JavaHashMap.of(Object.entries(revokedOut)).toJsonObject();
	}

	// constructor checks (thrown as IllegalArgumentException / NullPointerException in Java, wrapped into a
	// ParseException with the same message by the parse methods)
	if (use != null && ops != null && KEY_USE_OPS[use] && !ops.every((op) => KEY_USE_OPS[use].includes(op))) {
		throw new ParseException(
			'The key use "use" and key options "key_ops" parameters are not consistent, see RFC 7517, section 4.3',
		);
	}
	let firstCert: X509Certificate | null = null;
	if (x5c != null) {
		for (let i = 0; i < x5c.length; i++) {
			try {
				const cert = new X509Certificate(Buffer.from(x5c[i], "base64"));
				if (i === 0) {
					firstCert = cert;
				}
			} catch (e) {
				throw new ParseException(
					'Invalid X.509 certificate chain "x5c": Invalid X.509 certificate at position ' +
						i +
						": " +
						(e as Error).message,
				);
			}
		}
	}

	const certMismatch =
		"The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters";
	if (kty === "EC") {
		if (params["x"] == null) {
			throw new ParseException("The x coordinate must not be null");
		}
		if (params["y"] == null) {
			throw new ParseException("The y coordinate must not be null");
		}
		if (!EC_SUPPORTED_CURVES.includes(crv as string)) {
			throw new ParseException("Unknown / unsupported curve: " + crv);
		}
		try {
			createPublicKey({ key: { kty: "EC", crv: crv as string, x: params["x"], y: params["y"] }, format: "jwk" });
		} catch {
			throw new ParseException("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the " + crv + " curve");
		}
		if (firstCert != null) {
			const certJwk = certPublicJwk(firstCert);
			if (
				certJwk?.kty !== "EC" ||
				!sameBigInteger(params["x"], certJwk.x as string) ||
				!sameBigInteger(params["y"], certJwk.y as string)
			) {
				throw new ParseException(certMismatch);
			}
		}
	} else if (kty === "RSA") {
		if (params["n"] == null) {
			throw new ParseException("The modulus value must not be null");
		}
		if (params["e"] == null) {
			throw new ParseException("The public exponent value must not be null");
		}
		if (firstCert != null) {
			const certJwk = certPublicJwk(firstCert);
			if (
				certJwk?.kty !== "RSA" ||
				!sameBigInteger(params["e"], certJwk.e as string) ||
				!sameBigInteger(params["n"], certJwk.n as string)
			) {
				throw new ParseException(certMismatch);
			}
		}
		const crt = ["p", "q", "dp", "dq", "qi"].map((p) => params[p]);
		const allSet = crt.every((v) => v != null);
		const noneSet = crt.every((v) => v == null);
		if (!allSet && !noneSet) {
			const names = [
				"The first prime factor",
				"The second prime factor",
				"The first factor CRT exponent",
				"The second factor CRT exponent",
				"The first CRT coefficient",
			];
			const missing = crt.findIndex((v) => v == null);
			throw new ParseException(
				"Incomplete second private (CRT) representation: " + names[missing] + " must not be null",
			);
		}
	} else if (kty === "OKP") {
		if (!OKP_SUPPORTED_CURVES.includes(crv as string)) {
			throw new ParseException("Unknown / unsupported curve: " + crv);
		}
		if (params["x"] == null) {
			throw new ParseException("The x parameter must not be null");
		}
	} else if (params["k"] == null) {
		throw new ParseException("The key value must not be null");
	}

	// JWK.toJSONObject()
	const out: JsonObject = { kty }; // JWK.toJSONObject() puts in this order into a HashMap
	if (use != null) {
		out["use"] = use;
	}
	if (ops != null) {
		out["key_ops"] = ops;
	}
	if (alg != null) {
		out["alg"] = alg;
	}
	if (kid != null) {
		out["kid"] = kid;
	}
	if (x5u != null) {
		out["x5u"] = x5u;
	}
	if (x5t != null) {
		out["x5t"] = x5t;
	}
	if (x5t256 != null) {
		out["x5t#S256"] = x5t256;
	}
	if (x5c != null) {
		out["x5c"] = x5c;
	}
	if (exp != null) {
		out["exp"] = exp;
	}
	if (nbf != null) {
		out["nbf"] = nbf;
	}
	if (iat != null) {
		out["iat"] = iat;
	}
	if (revoked != null) {
		out["revoked"] = revoked;
	}
	if (kty === "EC" || kty === "OKP") {
		out["crv"] = crv;
	}
	for (const p of typeParams[kty]) {
		if (params[p] != null) {
			out[p] = params[p];
		}
	}
	if (oth != null && oth.length > 0 && params["p"] != null) {
		out["oth"] = oth
			.filter((x) => isJsonObject(x))
			.map((x) => JavaHashMap.of(Object.entries({ r: x["r"], d: x["d"], t: x["t"] })).toJsonObject());
	}
	return JavaHashMap.of(Object.entries(out)).toJsonObject() as JWK;
}

/** Member order of Nimbus JWK.toJSONObject() before hashing. */
const JWK_MEMBER_ORDER = [
	"kty",
	"use",
	"key_ops",
	"alg",
	"kid",
	"x5u",
	"x5t",
	"x5t#S256",
	"x5c",
	"exp",
	"nbf",
	"iat",
	"revoked",
	"crv",
	"x",
	"y",
	"n",
	"e",
	"d",
	"p",
	"q",
	"dp",
	"dq",
	"qi",
	"oth",
	"k",
];

/** Re-orders JWK members as Nimbus' toJSONObject() does (unknown members kept, after the known ones). */
export function nimbusJwkOrder(jwk: JsonObject): JWK {
	const entries: [string, JsonValue][] = [];
	for (const name of JWK_MEMBER_ORDER) {
		if (name in jwk) {
			entries.push([name, jwk[name]]);
		}
	}
	for (const [k, v] of Object.entries(jwk)) {
		if (!JWK_MEMBER_ORDER.includes(k)) {
			entries.push([k, v]);
		}
	}
	return JavaHashMap.of(entries).toJsonObject() as JWK;
}

/** Nimbus JWKSet.toJSONObject(): custom members (a HashMap) put first, then "keys". */
export function nimbusJwkSetJson(customMembers: [string, JsonValue][], keys: JsonValue[]): JsonObject {
	const custom = JavaHashMap.of(customMembers);
	const o = new JavaHashMap();
	o.putAll(custom.entries());
	o.put("keys", keys);
	return o.toJsonObject();
}

function certPublicJwk(cert: X509Certificate): JsonObject | null {
	try {
		return cert.publicKey.export({ format: "jwk" }) as JsonObject;
	} catch {
		return null;
	}
}

const PRIVATE_MEMBERS_BY_KTY: Record<string, string[]> = {
	EC: ["d"],
	OKP: ["d"],
	RSA: ["d", "p", "q", "dp", "dq", "qi", "oth"],
};

/**
 * Nimbus `JWK.parse(String)` / `JWK.parse(Map)`: validates a single key with Nimbus' rules and error messages and
 * returns its normalized JSON form (Nimbus `JWK.toJSONObject()`).
 *
 * @throws ParseException
 */
export function parseJWK(jwk: string | JsonObject): JWK {
	const json = typeof jwk === "string" ? nimbusParseJsonObject(jwk) : jwk;
	return parseJWKObject(json);
}

/**
 * Nimbus `JWKSet.parse(String)` / `JWKSet.parse(Map)`: strict parsing with Nimbus' error messages. Keys with an
 * unknown `kty` are silently dropped (RFC 7517 section 5) as Nimbus does. Returns the JSON form of the parsed set
 * (Nimbus `JWKSet.toJSONObject(false)`: custom top-level members first, then `keys`).
 *
 * @throws ParseException
 */
export function parseJWKSet(jwksString: string | JsonObject): JWKSet {
	const json = typeof jwksString === "string" ? nimbusParseJsonObject(jwksString) : jwksString;
	const keyArray = nimbusGetJSONArray(json, "keys");
	if (keyArray == null) {
		throw new ParseException('Missing required "keys" member');
	}
	const keys: JWK[] = [];
	for (let i = 0; i < keyArray.length; i++) {
		const keyJSONObject = keyArray[i];
		if (!isJsonObject(keyJSONObject)) {
			throw new ParseException('The "keys" JSON array must contain JSON objects only');
		}
		try {
			keys.push(parseJWKObject(keyJSONObject));
		} catch (e) {
			if (e instanceof ParseException) {
				if (e.message.startsWith("Unsupported key type")) {
					// Ignore unknown key type
					// https://tools.ietf.org/html/rfc7517#section-5
					continue;
				}
				throw new ParseException("Invalid JWK at position " + i + ": " + e.message);
			}
			throw e;
		}
	}
	// Parse additional custom members
	const additionalMembers = Object.entries(json).filter(([k]) => k !== "keys");
	return nimbusJwkSetJson(additionalMembers, keys) as JWKSet;
}

/**
 * Nimbus `JWKSet.toJSONObject(publicKeysOnly)` on a JSON JWK set (keys are normalized via Nimbus parsing; with
 * `publicKeysOnly` the symmetric keys are dropped and the private members removed).
 */
export function jwkSetToJSONObject(jwks: JsonObject, publicKeysOnly: boolean): JsonObject {
	const a: JsonArray = [];
	const keys = jwks["keys"];
	for (const key of isJsonArray(keys) ? keys : []) {
		const jwk = parseJWKObject(key as JsonObject);
		if (publicKeysOnly) {
			// Try to get public key, then serialise
			const publicKey = toPublicJWK(jwk);
			if (publicKey != null) {
				a.push(publicKey);
			}
		} else {
			a.push(jwk);
		}
	}
	return nimbusJwkSetJson(
		Object.entries(jwks).filter(([k]) => k !== "keys"),
		a,
	);
}

/** Nimbus `JWK.toPublicJWK()`: a copy without the private members, or null for a symmetric (oct) key. */
export function toPublicJWK(jwk: JsonObject): JWK | null {
	const kty = jwk["kty"];
	if (kty === "oct") {
		return null;
	}
	const out: JsonObject = {};
	const privateMembers = PRIVATE_MEMBERS_BY_KTY[kty as string] ?? [];
	for (const [k, v] of Object.entries(jwk)) {
		if (!privateMembers.includes(k)) {
			out[k] = v;
		}
	}
	return nimbusJwkOrder(out);
}

/** Nimbus `JWK.isPrivate()`: true when the key carries private (or symmetric) key material. */
export function isPrivate(jwk: JsonObject): boolean {
	if (jwk["kty"] === "oct") {
		return true;
	}
	return (PRIVATE_MEMBERS_BY_KTY[jwk["kty"] as string] ?? []).some((m) => jwk[m] != null);
}

/**
 * Nimbus `JWK.getRequiredParams()`: the RFC 7638 thumbprint members of the key, in lexicographic order. (Was a
 * table local to VerifyNewJwksHasNewSigningKey.)
 */
export function getRequiredParams(jwk: JsonObject): JsonObject {
	const out: JsonObject = {};
	for (const param of REQUIRED_PARAMS[jwk["kty"] as string] ?? []) {
		out[param] = jwk[param];
	}
	return out;
}

const REQUIRED_PARAMS: Record<string, string[]> = {
	RSA: ["e", "kty", "n"],
	EC: ["crv", "kty", "x", "y"],
	OKP: ["crv", "kty", "x"],
	oct: ["k", "kty"],
};

/**
 * Converts a JSON JWK into a jose key (`CryptoKey`, or `Uint8Array` for oct keys) for use with jose
 * sign/verify/encrypt/decrypt. Replaces Nimbus `toRSAPublicKey()`, `toECPrivateKey()`, `toSecretKey()` etc.
 * The JWK's `use`, `key_ops`, `ext` (and `alg`, when `alg` is given) are not passed to jose, because jose
 * (WebCrypto) rejects a key whose metadata does not match the requested operation while Nimbus does not.
 * Async because jose's `importJWK` is.
 */
export async function importKey(jwk: JsonObject, alg?: string): Promise<CryptoKey | Uint8Array> {
	const { use: _use, key_ops: _ops, ext: _ext, ...rest } = jwk;
	const keyAlg = alg ?? (typeof jwk["alg"] === "string" ? jwk["alg"] : undefined);
	const key = await importJWK({ ...rest, ...(keyAlg ? { alg: keyAlg } : {}) } as JoseJWK, keyAlg, {
		extractable: true,
	});
	return key;
}

/**
 * The `x5t#S256` test of Nimbus `JWKMatcher.matches`: the key matches on its own `x5t#S256`, or on the SHA-256
 * thumbprint of the first certificate of its `x5c` chain (an unparseable certificate is ignored).
 */
export function matchesX5tS256(jwk: JsonObject, x5tS256: string): boolean {
	let matchingCertFound = false;
	const x5c = jwk["x5c"];
	if (Array.isArray(x5c) && x5c.length > 0) {
		try {
			const cert = new X509Certificate(Buffer.from(String(x5c[0]), "base64"));
			matchingCertFound = createHash("sha256").update(cert.raw).digest("base64url") === x5tS256;
		} catch {
			// Ignore
		}
	}
	const matchingX5T256Found = jwk["x5t#S256"] === x5tS256;
	return matchingCertFound || matchingX5T256Found;
}

/** JWKMatcher.Builder().keyUses(KeyUse.SIGNATURE, null) */
function useMatches(jwk: JWK): boolean {
	return jwk["use"] == null || jwk["use"] === "sig";
}

/**
 * Nimbus `JWKMatcher.forJWSHeader(header)` as a predicate over JSON JWKs, or null for an algorithm outside the RSA,
 * EC, HMAC_SHA and ED families ("Unsupported algorithm").
 *
 * - RSA / EC: key type, `kid` (when the header has one), `use` sig or absent, `alg` equal or absent, and the
 *   header's `x5t#S256` (when present) via {@link matchesX5tS256}.
 * - HMAC: key type, `kid`, `alg`, and `privateOnly` (always true for an oct key); no `use` restriction.
 * - ED: key type, `kid`, `use`, `alg`, and the curves of {@link curvesForJWSAlgorithm} (null = any curve).
 *
 * The `kid` and `x5t#S256` header values are only used when they are strings: the Nimbus header parsing (see
 * `nimbus/jwt.ts`) rejects any other type, so a header that got this far never has one.
 */
export function jwkMatcherForJWSHeader(header: JsonObject): ((jwk: JWK) => boolean) | null {
	const alg = header["alg"] as string;
	const kid = typeof header["kid"] === "string" ? header["kid"] : null;
	const x5tS256 = typeof header["x5t#S256"] === "string" ? header["x5t#S256"] : null;
	const kty = keyTypeForAlgorithm(alg);
	// JWKMatcher.Builder().keyID(id): no restriction for a null id, else Set.contains(key.getKeyID())
	const kidMatches = (jwk: JWK) => kid == null || jwk["kid"] === kid;
	// .algorithms(algorithm, null)
	const algMatches = (jwk: JWK) => jwk["alg"] == null || jwk["alg"] === alg;
	if (JWS_FAMILY_RSA.includes(alg) || JWS_FAMILY_EC.includes(alg)) {
		// RSA or EC key matcher
		return (jwk) =>
			jwk["kty"] === kty &&
			useMatches(jwk) &&
			algMatches(jwk) &&
			kidMatches(jwk) &&
			(x5tS256 == null || matchesX5tS256(jwk, x5tS256));
	} else if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		// HMAC secret matcher
		return (jwk) => isPrivate(jwk) && jwk["kty"] === kty && algMatches(jwk) && kidMatches(jwk);
	} else if (JWS_FAMILY_ED.includes(alg)) {
		const curves = curvesForJWSAlgorithm(alg);
		return (jwk) =>
			jwk["kty"] === kty &&
			useMatches(jwk) &&
			algMatches(jwk) &&
			kidMatches(jwk) &&
			(curves == null || curves.includes(jwk["crv"] as string));
	}
	return null; // Unsupported algorithm
}
