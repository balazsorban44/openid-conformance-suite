import { createPublicKey, X509Certificate } from "node:crypto";
import { importJWK, type CryptoKey, type JWK as JoseJWK } from "jose";
import type { Environment } from "../framework/Environment.ts";
import {
	isJsonArray,
	isJsonObject,
	OIDFJSON,
	parseJsonObject,
	type JsonArray,
	type JsonObject,
	type JsonValue,
} from "../framework/json.ts";

/**
 * A JSON Web Key as plain JSON. Replaces Nimbus `com.nimbusds.jose.jwk.JWK` (and its subclasses `RSAKey`,
 * `ECKey`, `OctetKeyPair`, `OctetSequenceKey`). It is both a {@link JsonObject} (so it can be stored in the
 * environment as is) and a jose `JWK` (so it can be passed to `importJWK`).
 */
export type JWK = JsonObject & JoseJWK;

/** A JSON Web Key set as plain JSON. Replaces Nimbus `com.nimbusds.jose.jwk.JWKSet`. */
export type JWKSet = JsonObject & { keys: JWK[] };

/** Port of `java.text.ParseException`, thrown where Nimbus parse methods throw it. */
export class ParseException extends Error {
	readonly errorOffset: number;

	constructor(message: string, errorOffset = 0, options?: ErrorOptions) {
		super(message, options);
		this.name = "ParseException";
		this.errorOffset = errorOffset;
	}

	getErrorOffset(): number {
		return this.errorOffset;
	}
}

/** Port of `org.openqa.selenium.InvalidArgumentException` as thrown by JWKUtil. */
export class InvalidArgumentException extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidArgumentException";
	}
}

/** A JWK that {@link JWKUtil.parseJWKSetLeniently} skipped, with the reason the JOSE library rejected it. */
export class SkippedJwk {
	readonly keyJson: JsonValue;
	readonly reason: string;

	constructor(keyJson: JsonValue, reason: string) {
		this.keyJson = keyJson;
		this.reason = reason;
	}
}

/** A problem found with a single key in a JWK set, identified by its position (index) within the set. */
export class JwkIssue {
	readonly index: number;
	readonly key: JsonValue;
	readonly detail: string;

	constructor(index: number, key: JsonValue, detail: string) {
		this.index = index;
		this.key = key;
		this.detail = detail;
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Nimbus algorithm families (com.nimbusds.jose.JWSAlgorithm.Family / JWEAlgorithm.Family), as explicit lists.
// ---------------------------------------------------------------------------------------------------------------

/** JWSAlgorithm.Family.HMAC_SHA */
export const JWS_FAMILY_HMAC_SHA: readonly string[] = ["HS256", "HS384", "HS512"];
/** JWSAlgorithm.Family.RSA */
export const JWS_FAMILY_RSA: readonly string[] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];
/** JWSAlgorithm.Family.EC */
export const JWS_FAMILY_EC: readonly string[] = ["ES256", "ES256K", "ES384", "ES512"];
/** JWSAlgorithm.Family.ED */
export const JWS_FAMILY_ED: readonly string[] = ["EdDSA", "Ed25519", "Ed448"];
/** JWSAlgorithm.Family.SIGNATURE (RSA + EC + ED) */
export const JWS_FAMILY_SIGNATURE: readonly string[] = [...JWS_FAMILY_RSA, ...JWS_FAMILY_EC, ...JWS_FAMILY_ED];

/** JWEAlgorithm.Family.RSA */
export const JWE_FAMILY_RSA: readonly string[] = ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512"];
/** JWEAlgorithm.Family.AES_KW */
export const JWE_FAMILY_AES_KW: readonly string[] = ["A128KW", "A192KW", "A256KW"];
/** JWEAlgorithm.Family.ECDH_ES */
export const JWE_FAMILY_ECDH_ES: readonly string[] = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"];
/** JWEAlgorithm.Family.ECDH_1PU */
export const JWE_FAMILY_ECDH_1PU: readonly string[] = [
	"ECDH-1PU",
	"ECDH-1PU+A128KW",
	"ECDH-1PU+A192KW",
	"ECDH-1PU+A256KW",
];
/** JWEAlgorithm.Family.AES_GCM_KW */
export const JWE_FAMILY_AES_GCM_KW: readonly string[] = ["A128GCMKW", "A192GCMKW", "A256GCMKW"];
/** JWEAlgorithm.Family.PBES2 */
export const JWE_FAMILY_PBES2: readonly string[] = ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"];
/** JWEAlgorithm.Family.ASYMMETRIC (RSA + ECDH_ES) */
export const JWE_FAMILY_ASYMMETRIC: readonly string[] = [...JWE_FAMILY_RSA, ...JWE_FAMILY_ECDH_ES];
/** JWEAlgorithm.Family.SYMMETRIC (AES_KW + AES_GCM_KW + dir) */
export const JWE_FAMILY_SYMMETRIC: readonly string[] = [...JWE_FAMILY_AES_KW, ...JWE_FAMILY_AES_GCM_KW, "dir"];

/** EncryptionMethod.Family.AES_CBC_HMAC_SHA */
export const ENC_FAMILY_AES_CBC_HMAC_SHA: readonly string[] = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"];
/** EncryptionMethod.Family.AES_GCM */
export const ENC_FAMILY_AES_GCM: readonly string[] = ["A128GCM", "A192GCM", "A256GCM"];

/**
 * @internal Nimbus `JWSAlgorithm.parse(null)` / `JWEAlgorithm.parse(null)` / `EncryptionMethod.parse(null)` throw a
 * NullPointerException; the predicates built on them do the same.
 */
export function requireAlgorithmName(name: string | null | undefined): string {
	if (name == null) {
		throw new TypeError('Cannot invoke "String.equals(Object)" because "s" is null');
	}
	return name;
}

// ---------------------------------------------------------------------------------------------------------------
// Minimal port of the Nimbus JSON / JWK parsing semantics (JSONObjectUtils, JWK.parse, JWKSet.parse,
// JWK.toJSONObject). The JSON form produced here has the same members, in the same order, as Nimbus'
// toJSONObject(): members Nimbus does not know are dropped, as they are when Java round-trips via Nimbus.
// ---------------------------------------------------------------------------------------------------------------

/** Nimbus JSONObjectUtils.getGeneric: null when missing or JSON null; throws on a wrong type. */
function nimbusGet<T>(o: JsonObject, name: string, check: (v: JsonValue) => v is T & JsonValue): T | null {
	const value = o[name];
	if (value == null) {
		return null;
	}
	if (!check(value)) {
		throw new ParseException("Unexpected type of JSON object member " + name + "");
	}
	return value;
}

const isStr = (v: JsonValue): v is string => typeof v === "string";
const isNum = (v: JsonValue): v is number => typeof v === "number";
const isBool = (v: JsonValue): v is boolean => typeof v === "boolean";
const isArr = (v: JsonValue): v is JsonArray => Array.isArray(v);
const isObj = (v: JsonValue): v is JsonObject => isJsonObject(v);

/** @internal Nimbus JSONObjectUtils.getString */
export function nimbusGetString(o: JsonObject, name: string): string | null {
	return nimbusGet(o, name, isStr);
}

/** @internal Nimbus JSONObjectUtils.getJSONArray */
export function nimbusGetJSONArray(o: JsonObject, name: string): JsonArray | null {
	return nimbusGet(o, name, isArr);
}

/** @internal Nimbus JSONObjectUtils.getJSONObject */
export function nimbusGetJSONObject(o: JsonObject, name: string): JsonObject | null {
	return nimbusGet(o, name, isObj);
}

/** @internal Nimbus JSONObjectUtils.getBoolean (throws when missing) */
export function nimbusGetBoolean(o: JsonObject, name: string): boolean {
	const v = nimbusGet(o, name, isBool);
	if (v == null) {
		throw new ParseException("JSON object member " + name + " is missing or null");
	}
	return v;
}

/** @internal Nimbus JSONObjectUtils.getLong / getInt (throws when missing; truncates like Number.longValue()) */
export function nimbusGetLong(o: JsonObject, name: string): number {
	const v = nimbusGet(o, name, isNum);
	if (v == null) {
		throw new ParseException("JSON object member " + name + " is missing or null");
	}
	return Math.trunc(v);
}

/** @internal Nimbus JSONObjectUtils.getStringList */
export function nimbusGetStringList(o: JsonObject, name: string): (string | null)[] | null {
	const arr = nimbusGetJSONArray(o, name);
	if (arr == null) {
		return null;
	}
	for (const item of arr) {
		if (item !== null && typeof item !== "string") {
			throw new ParseException("JSON object member " + name + " is not an array of strings");
		}
	}
	return arr as (string | null)[];
}

/** @internal Nimbus JSONObjectUtils.getURI (java.net.URI syntax check, approximated) */
export function nimbusGetURI(o: JsonObject, name: string): string | null {
	const value = nimbusGetString(o, name);
	if (value == null) {
		return null;
	}
	// java.net.URI rejects whitespace, control characters and a few ASCII punctuation characters
	const m = /[\s"<>\\^`{|}\u0000-\u001f\u007f]/.exec(value);
	if (m) {
		throw new ParseException("Illegal character in URI at index " + m.index + ": " + value);
	}
	return value;
}

/**
 * @internal Nimbus JSONObjectUtils.parse(String): strict JSON, the top level must be an object and duplicate member
 * names are rejected (Gson's map adapter throws on them). Any failure is "Invalid JSON object".
 */
export function nimbusParseJsonObject(s: string, sizeLimit = -1): JsonObject {
	if (s.trim().length === 0) {
		throw new ParseException("Invalid JSON object");
	}
	if (sizeLimit >= 0 && s.length > sizeLimit) {
		throw new ParseException("The parsed string is longer than the max accepted size of " + sizeLimit + " characters");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(s);
	} catch {
		throw new ParseException("Invalid JSON object");
	}
	if (!isJsonObject(parsed) || hasDuplicateKeys(s)) {
		throw new ParseException("Invalid JSON object");
	}
	return parsed;
}

/** Scans already-valid JSON text for an object with a repeated member name. */
function hasDuplicateKeys(text: string): boolean {
	let i = 0;
	const skipWs = () => {
		while (i < text.length && " \t\n\r".includes(text[i])) {
			i++;
		}
	};
	const readString = (): string => {
		const start = i;
		i++; // opening quote
		while (text[i] !== '"') {
			if (text[i] === "\\") {
				i++;
			}
			i++;
		}
		i++; // closing quote
		return JSON.parse(text.slice(start, i)) as string;
	};
	const readValue = (): boolean => {
		skipWs();
		const c = text[i];
		if (c === "{") {
			i++;
			const seen = new Set<string>();
			skipWs();
			if (text[i] === "}") {
				i++;
				return false;
			}
			for (;;) {
				skipWs();
				const key = readString();
				if (seen.has(key)) {
					return true;
				}
				seen.add(key);
				skipWs();
				i++; // ':'
				if (readValue()) {
					return true;
				}
				skipWs();
				if (text[i] === ",") {
					i++;
					continue;
				}
				i++; // '}'
				return false;
			}
		}
		if (c === "[") {
			i++;
			skipWs();
			if (text[i] === "]") {
				i++;
				return false;
			}
			for (;;) {
				if (readValue()) {
					return true;
				}
				skipWs();
				if (text[i] === ",") {
					i++;
					continue;
				}
				i++; // ']'
				return false;
			}
		}
		if (c === '"') {
			readString();
			return false;
		}
		while (i < text.length && !",]} \t\n\r".includes(text[i])) {
			i++;
		}
		return false;
	};
	return readValue();
}

const EC_SUPPORTED_CURVES = ["P-256", "secp256k1", "P-384", "P-521"];
const OKP_SUPPORTED_CURVES = ["Ed25519", "Ed448", "X25519", "X448"];
const KEY_OPERATIONS = ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"];
const KEY_USE_OPS: Record<string, string[]> = {
	sig: ["sign", "verify"],
	enc: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
};

/** Nimbus Curve.parse */
function parseCurve(s: string | null): string {
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
function nimbusParseJWK(o: JsonObject): JWK {
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
		revoked = revokedOut;
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
	const out: JsonObject = { kty };
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
		out["oth"] = oth.filter((x) => isJsonObject(x)).map((x) => ({ r: x["r"], d: x["d"], t: x["t"] }));
	}
	return out as JWK;
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

export class JWKUtil {
	/** Alias so `new JWKUtil.SkippedJwk(...)` works as in Java; the type is the exported {@link SkippedJwk}. */
	static readonly SkippedJwk = SkippedJwk;
	/** Alias so `new JWKUtil.JwkIssue(...)` works as in Java; the type is the exported {@link JwkIssue}. */
	static readonly JwkIssue = JwkIssue;

	/**
	 * Replaces Nimbus `JWKSet.parse(String)`: strict parsing with Nimbus' error messages. Keys with an unknown
	 * `kty` are silently dropped (RFC 7517 section 5) as Nimbus does. Returns the JSON form of the parsed set
	 * (Nimbus `JWKSet.toJSONObject(false)`: custom top-level members first, then `keys`).
	 * Also accepts an already parsed JSON object.
	 *
	 * @throws ParseException
	 */
	static parseJWKSet(jwksString: string | JsonObject): JWKSet {
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
				keys.push(nimbusParseJWK(keyJSONObject));
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
		const out: JsonObject = {};
		for (const [k, v] of Object.entries(json)) {
			if (k !== "keys") {
				out[k] = v;
			}
		}
		out["keys"] = keys;
		return out as JWKSet;
	}

	/**
	 * Replaces Nimbus `JWK.parse(String)` / `JWK.parse(Map)`: validates a single key with Nimbus' rules and error
	 * messages and returns its normalized JSON form (Nimbus `JWK.toJSONObject()`).
	 *
	 * @throws ParseException
	 */
	static parseJWK(jwk: string | JsonObject): JWK {
		const json = typeof jwk === "string" ? nimbusParseJsonObject(jwk) : jwk;
		return nimbusParseJWK(json);
	}

	/**
	 * Parse a JWK set, skipping any individual keys the JOSE library cannot handle (e.g. keys
	 * using curves it does not support, such as Brainpool). This mirrors how a real recipient
	 * would behave when offered a set of keys: ignore the ones it cannot use and keep the rest.
	 *
	 * Use this only when selecting a usable key from a counterparty's JWK set (e.g. picking an
	 * encryption key), NOT when validating a JWK set where every key is expected to be valid.
	 *
	 * Each skipped key - together with the reason the JOSE library could not parse it - is recorded
	 * in `skippedKeys`, so the calling condition can log it into the test log.
	 *
	 * @param jwksString the JWK set as a JSON string
	 * @param skippedKeys populated with one entry per key that could not be parsed
	 * @return a JWK set containing only the keys that parsed successfully (possibly empty)
	 * @throws ParseException if the JSON is not a valid JWK set object (missing "keys" array)
	 */
	static parseJWKSetLeniently(jwksString: string, skippedKeys: SkippedJwk[]): JWKSet {
		const jwks = parseJsonObject(jwksString);
		const keysElement = jwks["keys"];
		if (keysElement == null || !isJsonArray(keysElement)) {
			throw new ParseException('JWK set does not contain a "keys" array', 0);
		}
		const keys = keysElement;
		const parsed: JWK[] = [];
		for (const keyEl of keys) {
			try {
				parsed.push(JWKUtil.parseJWK(JSON.stringify(keyEl)));
			} catch (e) {
				if (!(e instanceof ParseException)) {
					throw e;
				}
				// skip keys the JOSE library cannot handle (e.g. unsupported curves or key types)
				skippedKeys.push(new SkippedJwk(keyEl, e.message));
			}
		}
		return { keys: parsed } as JWKSet;
	}

	private static readonly PRIVATE_KEY_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

	private static readonly SUPPORTED_KEY_TYPES = new Set(["EC", "RSA", "oct", "OKP"]);

	private static readonly KNOWN_ALGORITHMS = new Set<string>([
		...JWS_FAMILY_SIGNATURE,
		...JWE_FAMILY_ASYMMETRIC,
		...JWE_FAMILY_SYMMETRIC,
	]);

	private static readonly BASE64URL = /^[A-Za-z0-9_-]*$/;

	private static keysArrayOrEmpty(jwks: JsonObject | null | undefined): JsonArray {
		if (jwks != null) {
			const keys = jwks["keys"];
			if (keys != null && isJsonArray(keys)) {
				return keys;
			}
		}
		return [];
	}

	private static stringMember(key: JsonObject, member: string): string | null {
		const el = key[member];
		return el != null && !isJsonArray(el) && !isJsonObject(el) ? OIDFJSON.getString(el) : null;
	}

	/**
	 * Scan a JWK set for private or symmetric key material by inspecting the raw JSON members,
	 * deliberately NOT relying on the JOSE library to parse each key. `JWKSet.parse` /
	 * `JWK.parse` silently drop a key with an unknown `kty` (RFC 7517 section 5) and
	 * collapse every other failure into a single ParseException, so private material in a key the
	 * library cannot parse (e.g. on an unsupported curve) would otherwise go undetected.
	 *
	 * @return one issue per key that carries private (d/p/q/dp/dq/qi/oth/k) or symmetric (oct) material
	 */
	static findPrivateOrSymmetricKeyMembers(jwks: JsonObject | null): JwkIssue[] {
		const issues: JwkIssue[] = [];
		const keys = JWKUtil.keysArrayOrEmpty(jwks);
		for (let i = 0; i < keys.length; i++) {
			const keyEl = keys[i];
			if (!isJsonObject(keyEl)) {
				continue; // reported by findStructurallyInvalidKeys
			}
			const key = keyEl;
			if ("oct" === JWKUtil.stringMember(key, "kty")) {
				issues.push(new JwkIssue(i, keyEl, "is a symmetric (oct) key"));
				continue;
			}
			for (const member of JWKUtil.PRIVATE_KEY_MEMBERS) {
				if (member in key) {
					issues.push(new JwkIssue(i, keyEl, "contains private key material (member '" + member + "')"));
					break;
				}
			}
		}
		return issues;
	}

	/**
	 * Check that each key has the members required for its (recognised) key type and that the
	 * encoded coordinate values are unpadded base64url. Keys whose `kty` the JOSE library does
	 * not recognise are left to {@link JWKUtil.findUnusableKeys} (a warning), not reported here.
	 *
	 * @return one issue per structurally invalid key
	 */
	static findStructurallyInvalidKeys(jwks: JsonObject | null): JwkIssue[] {
		const issues: JwkIssue[] = [];
		const keys = JWKUtil.keysArrayOrEmpty(jwks);
		for (let i = 0; i < keys.length; i++) {
			const keyEl = keys[i];
			if (!isJsonObject(keyEl)) {
				issues.push(new JwkIssue(i, keyEl, "is not a JSON object"));
				continue;
			}
			const key = keyEl;
			const kty = JWKUtil.stringMember(key, "kty");
			if (kty == null) {
				issues.push(new JwkIssue(i, keyEl, "is missing the required 'kty' member"));
				continue;
			}
			let required: string[];
			let base64urlMembers: string[];
			if ("RSA" === kty) {
				required = ["e", "n"];
				base64urlMembers = ["e", "n"];
			} else if ("EC" === kty) {
				required = ["x", "y"];
				base64urlMembers = ["x", "y"];
			} else if ("OKP" === kty) {
				required = ["x", "crv"];
				base64urlMembers = ["x"];
			} else {
				continue; // oct handled by the private/symmetric check; unknown kty by the warning check
			}
			const missing = JWKUtil.firstMissingMember(key, ...required);
			if (missing != null) {
				issues.push(new JwkIssue(i, keyEl, "is missing the required '" + missing + "' member for a " + kty + " key"));
				continue;
			}
			const badMember = JWKUtil.firstNonBase64UrlMember(key, ...base64urlMembers);
			if (badMember != null) {
				issues.push(new JwkIssue(i, keyEl, "has a '" + badMember + "' value that is not valid unpadded base64url"));
			}
		}
		return issues;
	}

	/**
	 * Identify keys the JOSE library cannot use: an unrecognised key type, an unsupported curve, or
	 * an unrecognised `alg`. These are surfaced as warnings (a real recipient ignores keys it
	 * cannot use, RFC 7517 section 5) rather than failures.
	 *
	 * @return one issue per unusable key
	 */
	static findUnusableKeys(jwks: JsonObject | null): JwkIssue[] {
		const issues: JwkIssue[] = [];
		const keys = JWKUtil.keysArrayOrEmpty(jwks);
		for (let i = 0; i < keys.length; i++) {
			const keyEl = keys[i];
			if (!isJsonObject(keyEl)) {
				continue;
			}
			const key = keyEl;
			const kty = JWKUtil.stringMember(key, "kty");
			if (kty == null) {
				continue; // missing kty is a structural failure, reported elsewhere
			}
			if (!JWKUtil.SUPPORTED_KEY_TYPES.has(kty)) {
				issues.push(new JwkIssue(i, keyEl, "uses an unsupported key type (kty '" + kty + "')"));
			} else if ("EC" === kty) {
				const unsupported = JWKUtil.unsupportedCurve(key, EC_SUPPORTED_CURVES);
				if (unsupported != null) {
					issues.push(new JwkIssue(i, keyEl, "uses an unsupported EC curve ('" + unsupported + "')"));
				}
			} else if ("OKP" === kty) {
				const unsupported = JWKUtil.unsupportedCurve(key, OKP_SUPPORTED_CURVES);
				if (unsupported != null) {
					issues.push(new JwkIssue(i, keyEl, "uses an unsupported OKP curve ('" + unsupported + "')"));
				}
			}
			const alg = JWKUtil.stringMember(key, "alg");
			if (alg != null && alg.length > 0 && !JWKUtil.KNOWN_ALGORITHMS.has(alg)) {
				issues.push(new JwkIssue(i, keyEl, "uses an unrecognised algorithm (alg '" + alg + "')"));
			}
		}
		return issues;
	}

	private static unsupportedCurve(key: JsonObject, supported: string[]): string | null {
		const crv = JWKUtil.stringMember(key, "crv");
		if (crv == null || crv.length === 0) {
			return null; // missing/empty crv is a structural concern, not an "unusable" warning
		}
		return supported.includes(parseCurve(crv)) ? null : crv;
	}

	private static firstMissingMember(key: JsonObject, ...members: string[]): string | null {
		for (const member of members) {
			if (!(member in key)) {
				return member;
			}
		}
		return null;
	}

	private static firstNonBase64UrlMember(key: JsonObject, ...members: string[]): string | null {
		for (const member of members) {
			const value = JWKUtil.stringMember(key, member);
			if (value == null || !JWKUtil.isBase64Url(value)) {
				return member;
			}
		}
		return null;
	}

	/** True if `value` is non-null and contains only unpadded base64url characters. */
	static isBase64Url(value: string | null | undefined): boolean {
		return value != null && JWKUtil.BASE64URL.test(value);
	}

	/** True if `jwks` is a JSON object containing a "keys" array. */
	static hasKeysArray(jwks: JsonObject | null | undefined): boolean {
		const keys = jwks == null ? null : jwks["keys"];
		return keys != null && isJsonArray(keys);
	}

	/**
	 * Parse each *usable* key with the JOSE library, to apply the checks the structural scan does
	 * not (e.g. the x5c "bare key must match the certificate" check, and crypto-level validity). Keys
	 * the library cannot use (unknown kty, unsupported curve, unrecognised alg - see
	 * {@link JWKUtil.findUnusableKeys}) are skipped here, since they are surfaced as warnings
	 * rather than failures and would otherwise fail to parse for a reason that is not an error.
	 *
	 * @return one issue per usable key the JOSE library fails to parse
	 */
	static findUnparseableUsableKeys(jwks: JsonObject | null): JwkIssue[] {
		const unusableIndices = new Set<number>();
		for (const issue of JWKUtil.findUnusableKeys(jwks)) {
			unusableIndices.add(issue.index);
		}
		const issues: JwkIssue[] = [];
		const keys = JWKUtil.keysArrayOrEmpty(jwks);
		for (let i = 0; i < keys.length; i++) {
			if (unusableIndices.has(i)) {
				continue;
			}
			const keyEl = keys[i];
			if (!isJsonObject(keyEl)) {
				continue; // reported by findStructurallyInvalidKeys
			}
			try {
				JWKUtil.parseJWK(JSON.stringify(keyEl));
			} catch (e) {
				if (!(e instanceof ParseException)) {
					throw e;
				}
				issues.push(new JwkIssue(i, keyEl, "cannot be parsed by the JOSE library (" + e.message + ")"));
			}
		}
		return issues;
	}

	/** Render a list of {@link JwkIssue}s as a JSON array suitable for logging in condition args. */
	static issuesToJson(issues: JwkIssue[]): JsonArray {
		const arr: JsonArray = [];
		for (const issue of issues) {
			const o: JsonObject = {};
			o["index"] = issue.index;
			o["detail"] = issue.detail;
			if (issue.key != null) {
				o["key"] = issue.key;
			}
			arr.push(o);
		}
		return arr;
	}

	/**
	 * Replaces `jwks.toJSONObject(true)` on a Nimbus JWKSet: the public keys only (symmetric keys are dropped,
	 * private members removed), in Nimbus' member order.
	 */
	static getPublicJwksAsJsonObject(jwks: JsonObject): JsonObject {
		return JWKUtil.jwkSetToJSONObject(jwks, true);
	}

	/** Replaces `jwks.toJSONObject(false)` on a Nimbus JWKSet: all keys including private members. */
	static getPrivateJwksAsJsonObject(jwks: JsonObject): JsonObject {
		return JWKUtil.jwkSetToJSONObject(jwks, false);
	}

	/** Nimbus JWKSet.toJSONObject(publicKeysOnly) on a JSON JWK set (keys are normalized via Nimbus parsing). */
	private static jwkSetToJSONObject(jwks: JsonObject, publicKeysOnly: boolean): JsonObject {
		const o: JsonObject = {};
		for (const [k, v] of Object.entries(jwks)) {
			if (k !== "keys") {
				o[k] = v;
			}
		}
		const a: JsonArray = [];
		const keys = jwks["keys"];
		for (const key of isJsonArray(keys) ? keys : []) {
			const jwk = nimbusParseJWK(key as JsonObject);
			if (publicKeysOnly) {
				// Try to get public key, then serialise
				const publicKey = JWKUtil.toPublicJWK(jwk);
				if (publicKey != null) {
					a.push(publicKey);
				}
			} else {
				a.push(jwk);
			}
		}
		o["keys"] = a;
		return o;
	}

	/**
	 * Replaces Nimbus `JWK.toPublicJWK()`: a copy without the private members, or null for a symmetric (oct) key.
	 */
	static toPublicJWK(jwk: JsonObject): JWK | null {
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
		return out as JWK;
	}

	/** Replaces Nimbus `JWK.isPrivate()`: true when the key carries private (or symmetric) key material. */
	static isPrivate(jwk: JsonObject): boolean {
		if (jwk["kty"] === "oct") {
			return true;
		}
		return (PRIVATE_MEMBERS_BY_KTY[jwk["kty"] as string] ?? []).some((m) => jwk[m] != null);
	}

	/**
	 * Converts a JSON JWK into a jose key (`CryptoKey`, or `Uint8Array` for oct keys) for use with jose
	 * sign/verify/encrypt/decrypt. Replaces Nimbus `toRSAPublicKey()`, `toECPrivateKey()`, `toSecretKey()` etc.
	 * The JWK's `use`, `key_ops`, `ext` (and `alg`, when `alg` is given) are not passed to jose, because jose
	 * (WebCrypto) rejects a key whose metadata does not match the requested operation while Nimbus does not.
	 * Async because jose's `importJWK` is.
	 */
	static async importKey(jwk: JsonObject, alg?: string): Promise<CryptoKey | Uint8Array> {
		const { use: _use, key_ops: _ops, ext: _ext, ...rest } = jwk;
		const keyAlg = alg ?? (typeof jwk["alg"] === "string" ? jwk["alg"] : undefined);
		const key = await importJWK({ ...rest, ...(keyAlg ? { alg: keyAlg } : {}) } as JoseJWK, keyAlg, {
			extractable: true,
		});
		return key;
	}

	static getAlgFromClientJwks(env: Environment): string {
		const jwks = env.getObject("client_jwks") as JsonObject;
		const keys = jwks["keys"] as JsonArray;
		const key = keys[0] as JsonObject;
		return OIDFJSON.getString(key["alg"]);
	}

	static getAlgsFromJwks(jwks: JsonObject): JsonArray {
		const keys = jwks["keys"] as JsonArray;
		const algs: JsonArray = [];
		for (const key of keys) {
			algs.push(OIDFJSON.getString((key as JsonObject)["alg"]));
		}
		return algs;
	}

	/**
	 * Will select the first key with the correct type, use and alg if possible
	 * or will select the key with correct type and use
	 * or will select the key with correct type
	 * Note: Server jwks will probably contain only 1 matching key (we create it), but just in case...
	 *
	 * Replaces `selectAsymmetricJWSKey(JWSAlgorithm, List<JWK>)`: the algorithm is its name, keys are JSON JWKs.
	 * @return null if not found
	 */
	static selectAsymmetricJWSKey(jwsAlgorithm: string, keys: JsonObject[]): JWK | null {
		let bestMatch: JWK | null = null;
		let secondBestMatch: JWK | null = null;
		let thirdMatch: JWK | null = null;
		// an alternative to this code would be using nimbusds JWKMatcher
		const consider = (key: JWK): boolean => {
			if (key["use"] != null) {
				if ("sig" === key["use"]) {
					if (key["alg"] == null) {
						secondBestMatch = key;
					} else {
						if (key["alg"] === jwsAlgorithm) {
							//this is the best match
							bestMatch = key;
							return true;
						}
					}
				}
			} else {
				thirdMatch = key;
			}
			return false;
		};
		for (const k of keys) {
			const key = k as JWK;
			const kty = key["kty"];
			if (JWS_FAMILY_EC.includes(jwsAlgorithm) && "EC" === kty) {
				if ("ES256" === jwsAlgorithm && "P-256" !== key["crv"]) {
					continue;
				}
				if ("ES256K" === jwsAlgorithm && "secp256k1" !== key["crv"]) {
					continue;
				}
				if (consider(key)) {
					break;
				}
			} else if (JWS_FAMILY_ED.includes(jwsAlgorithm) && "OKP" === kty) {
				if (consider(key)) {
					break;
				}
			} else if (jwsAlgorithm.startsWith("PS") && "RSA" === kty) {
				if (consider(key)) {
					break;
				}
			} else if (jwsAlgorithm.startsWith("RS") && "RSA" === kty) {
				if (consider(key)) {
					break;
				}
			}
		}
		if (bestMatch != null) {
			return bestMatch;
		} else if (secondBestMatch != null) {
			return secondBestMatch;
		} else {
			return thirdMatch;
		}
	}

	/**
	 * Replaces `getSigningKey(JsonObject)` returning a Nimbus JWK: returns the normalized JSON JWK.
	 *
	 * @throws ParseException if the set cannot be parsed
	 * @throws InvalidArgumentException if there is no, or more than one, signing key
	 */
	static getSigningKey(jwks: JsonObject): JWK {
		let count = 0;
		let signingJwk: JWK | null = null;

		const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(jwks));
		for (const jwk of jwkSet.keys) {
			const use = jwk["use"];
			if (use != null && use !== "sig") {
				continue;
			}
			count++;
			signingJwk = jwk;
		}

		if (count === 0) {
			throw new InvalidArgumentException(
				"Did not find a key with 'use': 'sig' or no 'use' claim, no key available to sign jwt",
			);
		}
		if (count > 1) {
			throw new InvalidArgumentException(
				"Expected only one signing JWK in the set. Please ensure the signing key is the only one in the jwks, or that other keys have a 'use' other than 'sig'.",
			);
		}

		return signingJwk as JWK;
	}

	/**
	 * Creates a {@link JsonObject} with a keys array containing the JWK {@link JsonObject}.
	 * @param keys
	 * @return
	 */
	static createJwksObjectFromJwkObjects(...keys: JsonObject[]): JsonObject {
		if (keys == null) {
			throw new InvalidArgumentException("keys must not be null");
		}

		const jwks: JsonObject = {};
		const jwksKeys: JsonArray = [];
		for (const key of keys) {
			jwksKeys.push(key);
		}

		jwks["keys"] = jwksKeys;
		return jwks;
	}

	static toPublicJWKSet(input: JsonObject): JsonObject {
		try {
			const json = JSON.stringify(input);
			const fullSet = JWKUtil.parseJWKSet(json);
			return JWKUtil.jwkSetToJSONObject(fullSet, true);
		} catch (e) {
			throw new Error("Failed to convert JWKS to public version", { cause: e });
		}
	}
}
