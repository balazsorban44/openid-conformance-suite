import { OIDFJSON, type JsonObject, type JsonValue } from "../framework/json.ts";
import { JWEUtil } from "./JWEUtil.ts";
import {
	JWE_FAMILY_SYMMETRIC,
	JWKUtil,
	nimbusGetBoolean,
	nimbusGetJSONArray,
	nimbusGetJSONObject,
	nimbusGetLong,
	nimbusGetString,
	nimbusGetStringList,
	nimbusGetURI,
	nimbusParseJsonObject,
	ParseException,
	type JWK,
} from "./JWKUtil.ts";

export { ParseException } from "./JWKUtil.ts";

/**
 * A parsed (not verified, not decrypted) compact JOSE object. Replaces the Nimbus `JWT` interface and its
 * implementations `PlainJWT` (`type: "plain"`), `SignedJWT` (`type: "signed"`) and `EncryptedJWT`
 * (`type: "encrypted"`), as returned by `JWTParser.parse` / `JWTUtil.parseJWT`, and `JWEObject` as returned by
 * `JWEObject.parse`.
 *
 * - `jwt instanceof EncryptedJWT` -> `jwt.type === "encrypted"`
 * - `jwt.getHeader().toJSONObject()` -> `jwt.header` (or `JWTUtil.jwtHeaderAsJsonObject(jwt)`)
 * - `jwt.getHeader().getAlgorithm().getName()` -> `jwt.header["alg"]`
 * - `jwt.getJWTClaimsSet()` -> `JWTUtil.jwtClaimsSetAsJsonObject(jwt)`
 * - `jwt.serialize()` / `jwt.getParsedString()` -> `jwt.serialized` (pass it to jose `compactVerify` /
 *   `compactDecrypt`)
 */
export interface JWT {
	type: "plain" | "signed" | "encrypted";
	/** The compact serialization that was parsed. */
	serialized: string;
	/** The base64url encoded parts (3 for plain/signed, 5 for encrypted). */
	parts: string[];
	/** The protected header as Nimbus serializes it (`Header.toJSONObject()`). */
	header: JsonObject;
	/** The decoded (UTF-8) payload for plain and signed JWTs; null for encrypted ones. */
	payload: string | null;
	/** The base64url signature for signed JWTs; null otherwise. */
	signature: string | null;
}

// ---------------------------------------------------------------------------------------------------------------
// Minimal port of the Nimbus compact serialization parsing (JWTParser, JOSEObject.split, *Header.parse).
// ---------------------------------------------------------------------------------------------------------------

const MAX_HEADER_STRING_LENGTH = 20_000;

function decodeToString(b64url: string): string {
	return Buffer.from(b64url, "base64url").toString("utf8");
}

/** Nimbus JOSEObject.split */
function split(s: string): string[] {
	const t = s.trim();

	// We must have 2 (JWS) or 4 dots (JWE)
	const dot1 = t.indexOf(".");
	if (dot1 === -1) {
		throw new ParseException("Invalid serialized unsecured/JWS/JWE object: Missing part delimiters");
	}
	const dot2 = t.indexOf(".", dot1 + 1);
	if (dot2 === -1) {
		throw new ParseException("Invalid serialized unsecured/JWS/JWE object: Missing second delimiter");
	}
	// Third dot for JWE only
	const dot3 = t.indexOf(".", dot2 + 1);
	if (dot3 === -1) {
		// Two dots only? -> We have a JWS
		return [t.substring(0, dot1), t.substring(dot1 + 1, dot2), t.substring(dot2 + 1)];
	}
	// Fourth final dot for JWE
	const dot4 = t.indexOf(".", dot3 + 1);
	if (dot4 === -1) {
		throw new ParseException("Invalid serialized JWE object: Missing fourth delimiter");
	}
	if (t.indexOf(".", dot4 + 1) !== -1) {
		throw new ParseException("Invalid serialized unsecured/JWS/JWE object: Too many part delimiters");
	}
	// Four dots -> five parts
	return [
		t.substring(0, dot1),
		t.substring(dot1 + 1, dot2),
		t.substring(dot2 + 1, dot3),
		t.substring(dot3 + 1, dot4),
		t.substring(dot4 + 1),
	];
}

/** Nimbus Header.parseAlgorithm: "none", or the JWE/JWS algorithm name (JWE when an "enc" member is present). */
function parseAlgorithm(json: JsonObject): { alg: string; kind: "plain" | "signed" | "encrypted" } {
	const algName = nimbusGetString(json, "alg");
	if (algName == null) {
		throw new ParseException('Missing "alg" in header JSON object');
	}
	if (algName === "none") {
		return { alg: algName, kind: "plain" };
	} else if ("enc" in json) {
		return { alg: algName, kind: "encrypted" };
	}
	return { alg: algName, kind: "signed" };
}

const COMMON_HEADER_PARAMS = ["alg", "typ", "cty", "crit"];
const SE_HEADER_PARAMS = ["jku", "jwk", "x5u", "x5t", "x5t#S256", "x5c", "kid"];
const JWS_HEADER_PARAMS = [...COMMON_HEADER_PARAMS, ...SE_HEADER_PARAMS, "b64"];
const JWE_HEADER_PARAMS = [
	...COMMON_HEADER_PARAMS,
	...SE_HEADER_PARAMS,
	"enc",
	"epk",
	"zip",
	"apu",
	"apv",
	"p2s",
	"p2c",
	"iv",
	"tag",
	"skid",
	"iss",
	"sub",
	"aud",
];

/**
 * Nimbus PlainHeader/JWSHeader/JWEHeader.parse(Map) followed by toJSONObject(): validates the registered
 * parameters (same messages as Nimbus) and returns the header in Nimbus' serialization order (custom parameters
 * first, registered ones without null values after).
 */
function parseHeader(json: JsonObject, kind: "plain" | "signed" | "encrypted"): JsonObject {
	const { alg, kind: algKind } = parseAlgorithm(json);
	if (kind === "plain" && algKind !== "plain") {
		throw new ParseException('The algorithm "alg" header parameter must be "none"');
	}
	if (kind === "signed" && algKind !== "signed") {
		throw new ParseException("Not a JWS header");
	}
	let enc: string | null = null;
	if (kind === "encrypted") {
		enc = nimbusGetString(json, "enc");
		if (enc == null) {
			throw new TypeError('The encryption method "enc" header parameter must not be null');
		}
	}
	const registered =
		kind === "plain" ? COMMON_HEADER_PARAMS : kind === "signed" ? JWS_HEADER_PARAMS : JWE_HEADER_PARAMS;

	const out: JsonObject = {};
	// custom parameters first
	for (const [name, value] of Object.entries(json)) {
		if (!registered.includes(name)) {
			out[name] = value;
		}
	}
	const putString = (name: string, value: string | null) => {
		if (value != null) {
			out[name] = value;
		}
	};
	out["alg"] = alg;
	putString("typ", nimbusGetString(json, "typ"));
	putString("cty", nimbusGetString(json, "cty"));
	const crit = nimbusGetStringList(json, "crit");
	if (crit != null && crit.length > 0) {
		out["crit"] = [...new Set(crit)];
	}
	if (kind === "plain") {
		return out;
	}
	putString("jku", nimbusGetURI(json, "jku"));
	const jwkJson = nimbusGetJSONObject(json, "jwk");
	if (jwkJson != null) {
		const jwk = JWKUtil.parseJWK(jwkJson);
		if (JWKUtil.isPrivate(jwk)) {
			throw new ParseException("Non-public key in jwk header parameter");
		}
		out["jwk"] = jwk;
	}
	putString("x5u", nimbusGetURI(json, "x5u"));
	putString("x5t", nimbusGetString(json, "x5t"));
	putString("x5t#S256", nimbusGetString(json, "x5t#S256"));
	const x5c = nimbusGetJSONArray(json, "x5c");
	if (x5c != null) {
		for (let i = 0; i < x5c.length; i++) {
			if (x5c[i] == null) {
				throw new ParseException("The X.509 certificate at position " + i + " must not be null");
			}
			if (typeof x5c[i] !== "string") {
				throw new ParseException("The X.509 certificate at position " + i + " must be encoded as a Base64 string");
			}
		}
		if (x5c.length > 0) {
			out["x5c"] = x5c;
		}
	}
	putString("kid", nimbusGetString(json, "kid"));
	if (kind === "signed") {
		if ("b64" in json && !nimbusGetBoolean(json, "b64")) {
			out["b64"] = false;
		}
		return out;
	}
	out["enc"] = enc;
	const epkJson = "epk" in json ? nimbusGetJSONObject(json, "epk") : null;
	if (epkJson != null) {
		out["epk"] = JWKUtil.parseJWK(epkJson);
	}
	putString("zip", nimbusGetString(json, "zip"));
	putString("apu", nimbusGetString(json, "apu"));
	putString("apv", nimbusGetString(json, "apv"));
	putString("p2s", nimbusGetString(json, "p2s"));
	if ("p2c" in json) {
		const p2c = nimbusGetLong(json, "p2c");
		if (p2c < 0) {
			throw new ParseException("The PBES2 count parameter must not be negative");
		}
		if (p2c > 0) {
			out["p2c"] = p2c;
		}
	}
	putString("iv", nimbusGetString(json, "iv"));
	putString("tag", nimbusGetString(json, "tag"));
	putString("skid", nimbusGetString(json, "skid"));
	putString("iss", nimbusGetString(json, "iss"));
	putString("sub", nimbusGetString(json, "sub"));
	if ("aud" in json) {
		const audValue = json["aud"];
		const aud = typeof audValue === "string" ? [audValue] : nimbusGetStringList(json, "aud");
		if (aud != null) {
			if (aud.length === 1) {
				out["aud"] = aud[0];
			} else if (aud.length > 0) {
				out["aud"] = aud;
			}
		}
	}
	return out;
}

function parseHeaderPart(part: string, kind: "plain" | "signed" | "encrypted"): JsonObject {
	return parseHeader(nimbusParseJsonObject(decodeToString(part), MAX_HEADER_STRING_LENGTH), kind);
}

/** Nimbus PlainJWT.parse / SignedJWT.parse / EncryptedJWT.parse */
function parseJOSEObject(s: string, kind: "plain" | "signed" | "encrypted"): JWT {
	const parts = split(s);
	if (kind === "plain") {
		if (parts[2].length !== 0) {
			throw new ParseException("Unexpected third Base64URL part in the unsecured JWT object");
		}
		let header: JsonObject;
		try {
			header = parseHeaderPart(parts[0], "plain");
		} catch (e) {
			throw new ParseException("Invalid unsecured header: " + (e as Error).message);
		}
		return { type: "plain", serialized: s, parts, header, payload: decodeToString(parts[1]), signature: null };
	}
	if (kind === "signed") {
		if (parts.length !== 3) {
			throw new ParseException("Unexpected number of Base64URL parts, must be three");
		}
		let header: JsonObject;
		try {
			header = parseHeaderPart(parts[0], "signed");
		} catch (e) {
			if (!(e instanceof ParseException)) {
				throw e;
			}
			throw new ParseException("Invalid JWS header: " + e.message);
		}
		if (parts[2].trim().length === 0) {
			throw new ParseException("The signature must not be empty");
		}
		return { type: "signed", serialized: s, parts, header, payload: decodeToString(parts[1]), signature: parts[2] };
	}
	if (parts.length !== 5) {
		throw new ParseException("Unexpected number of Base64URL parts, must be five");
	}
	let header: JsonObject;
	try {
		header = parseHeaderPart(parts[0], "encrypted");
	} catch (e) {
		if (!(e instanceof ParseException)) {
			throw e;
		}
		throw new ParseException("Invalid JWE header: " + e.message);
	}
	return { type: "encrypted", serialized: s, parts, header, payload: null, signature: null };
}

/** Nimbus JWTParser.parse */
function nimbusParseJWT(s: string): JWT {
	const firstDotPos = s.indexOf(".");
	if (firstDotPos === -1) {
		throw new ParseException("Invalid JWT serialization: Missing dot delimiter(s)");
	}
	let jsonObject: JsonObject;
	try {
		jsonObject = nimbusParseJsonObject(decodeToString(s.substring(0, firstDotPos)));
	} catch (e) {
		if (!(e instanceof ParseException)) {
			throw e;
		}
		throw new ParseException("Invalid unsecured/JWS/JWE header: " + e.message);
	}
	const { kind } = parseAlgorithm(jsonObject);
	return parseJOSEObject(s, kind);
}

/**
 * @internal Replaces Nimbus `JWEObject.parse(String)`.
 * @throws ParseException
 */
export function nimbusParseJWEObject(s: string): JWT {
	return parseJOSEObject(s, "encrypted");
}

/** Nimbus JWTClaimsSet.parse(Map) followed by toJSONObject(true) */
function claimsSetToJSONObject(json: JsonObject): JsonObject {
	const claims = new Map<string, JsonValue>();
	const dateClaims = new Set<string>();
	for (const name of Object.keys(json)) {
		switch (name) {
			case "iss":
				claims.set(name, nimbusGetString(json, "iss"));
				break;
			case "sub": {
				const subValue = json["sub"];
				if (typeof subValue === "string") {
					claims.set(name, subValue);
				} else if (typeof subValue === "number") {
					// Numbers not allowed per JWT spec, compromise
					// to enable interop with non-compliant libs
					// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
					claims.set(name, String(subValue));
				} else if (subValue == null) {
					claims.set(name, null);
				} else {
					throw new ParseException("Illegal sub claim");
				}
				break;
			}
			case "aud": {
				const audValue = json["aud"];
				if (typeof audValue === "string") {
					claims.set(name, [audValue]);
				} else if (Array.isArray(audValue)) {
					claims.set(name, nimbusGetStringList(json, "aud") as string[]);
				} else if (audValue == null) {
					claims.set(name, null);
				} else {
					throw new ParseException("Illegal aud claim");
				}
				break;
			}
			case "exp":
			case "nbf":
			case "iat": {
				const v = json[name] == null ? null : nimbusGetLong(json, name);
				claims.set(name, v);
				if (v != null) {
					dateClaims.add(name);
				} else {
					dateClaims.delete(name);
				}
				break;
			}
			case "jti":
				claims.set(name, nimbusGetString(json, "jti"));
				break;
			default:
				claims.set(name, json[name]);
				break;
		}
	}

	const o: JsonObject = {};
	for (const [key, value] of claims) {
		if (dateClaims.has(key)) {
			// Transform dates to Unix timestamps
			o[key] = value;
		} else if (key === "aud") {
			// Serialise single audience list and string
			const audList = value as string[] | null;
			if (audList != null && audList.length > 0) {
				if (audList.length === 1) {
					o["aud"] = audList[0];
				} else {
					o["aud"] = [...audList];
				}
			} else {
				o["aud"] = null;
			}
		} else {
			o[key] = value;
		}
	}
	return o;
}

export class JWTUtil {
	// 2024-01-01T00:00:00Z in seconds — any valid iat should be at least this recent
	private static readonly MIN_REASONABLE_TIMESTAMP = 1704067200;
	private static readonly SECONDS_PER_YEAR = 365 * 24 * 60 * 60;
	private static readonly CLOCK_SKEW_SECONDS = 5 * 60; // 5 minutes

	/**
	 * Validates an 'iat' (Issued At) claim value per RFC 7519.
	 * Checks that the value is a number, not before 2024 (catches millisecond timestamps),
	 * and not in the future (with 5 minutes clock skew tolerance).
	 *
	 * @param iat the raw claim value from the JWT payload (may be null)
	 * @return the validated timestamp in seconds
	 * @throws Error (IllegalArgumentException) if the value is missing, not a number, or out of range
	 */
	static validateIatClaim(iat: unknown): number {
		if (iat == null) {
			throw new Error("Missing 'iat' claim");
		}
		if (typeof iat !== "number") {
			throw new Error("'iat' claim is not a number");
		}
		const iatValue = Math.trunc(iat);
		if (iatValue < JWTUtil.MIN_REASONABLE_TIMESTAMP) {
			throw new Error(
				"'iat' claim value " +
					iatValue +
					" is too far in the past (this may indicate the value is not a unix timestamp in seconds)",
			);
		}
		const nowSeconds = Math.floor(Date.now() / 1000);
		if (iatValue > nowSeconds + JWTUtil.CLOCK_SKEW_SECONDS) {
			throw new Error("'iat' claim value " + iatValue + " is in the future (now: " + nowSeconds + ")");
		}
		return iatValue;
	}

	/**
	 * Validates an 'nbf' (Not Before) claim value per RFC 7519.
	 * Checks that the value is a number, not before 2024 (catches millisecond timestamps and
	 * epoch-default bugs), and not in the future (with 5 minutes clock skew tolerance).
	 *
	 * @param nbf the raw claim value from the JWT payload (may be null)
	 * @return the validated timestamp in seconds, or -1 if nbf is null (not present)
	 * @throws Error (IllegalArgumentException) if the value is not a number, out of range, or in the future
	 */
	static validateNbfClaim(nbf: unknown): number {
		if (nbf == null) {
			return -1;
		}
		if (typeof nbf !== "number") {
			throw new Error("'nbf' claim is not a number");
		}
		const nbfValue = Math.trunc(nbf);
		if (nbfValue < JWTUtil.MIN_REASONABLE_TIMESTAMP) {
			throw new Error(
				"'nbf' claim value " +
					nbfValue +
					" is too far in the past (this may indicate the value is not a unix timestamp in seconds)",
			);
		}
		const nowSeconds = Math.floor(Date.now() / 1000);
		if (nbfValue > nowSeconds + JWTUtil.CLOCK_SKEW_SECONDS) {
			throw new Error("'nbf' claim value " + nbfValue + " is in the future (now: " + nowSeconds + ")");
		}
		return nbfValue;
	}

	/**
	 * Validates an 'exp' (Expiration Time) claim value per RFC 7519.
	 * Checks that the value is a number, not more than 50 years in the future (catches millisecond timestamps),
	 * and not in the past (with 5 minutes clock skew tolerance).
	 *
	 * @param exp the raw claim value from the JWT payload (may be null)
	 * @return the validated timestamp in seconds, or -1 if exp is null (not present)
	 * @throws Error (IllegalArgumentException) if the value is not a number, out of range, or expired
	 */
	static validateExpClaim(exp: unknown): number {
		if (exp == null) {
			return -1;
		}
		if (typeof exp !== "number") {
			throw new Error("'exp' claim is not a number");
		}
		const expValue = Math.trunc(exp);
		const nowSeconds = Math.floor(Date.now() / 1000);
		const maxTimestamp = nowSeconds + 50 * JWTUtil.SECONDS_PER_YEAR;
		if (expValue > maxTimestamp) {
			throw new Error(
				"'exp' claim value " +
					expValue +
					" is too far in the future (this may indicate the value is not a unix timestamp in seconds)",
			);
		}
		if (expValue < nowSeconds - JWTUtil.CLOCK_SKEW_SECONDS) {
			throw new Error("'exp' claim value " + expValue + " indicates the JWT has expired (now: " + nowSeconds + ")");
		}
		return expValue;
	}

	/**
	 * wrapper for Nimbus JWTParser
	 * just in case we want to override something one day
	 *
	 * Returns a {@link JWT} (replaces Nimbus `JWT`); the header and payload are parsed with Nimbus' rules and error
	 * messages but nothing is verified or decrypted.
	 * @param jwtAsString
	 * @return
	 * @throws ParseException
	 */
	static parseJWT(jwtAsString: string): JWT {
		JWTUtil.validateJwtContainsOnlyAllowedCharacters(jwtAsString);
		const jwt = nimbusParseJWT(jwtAsString);
		return jwt;
	}

	/** @throws ParseException */
	static validateJwtContainsOnlyAllowedCharacters(jwt: string): void {
		// the allowed characters is base64url plus '.'
		const regex = /^[.a-zA-Z0-9_-]$/;
		// UPSTREAM: Java iterates UTF-16 chars, so a non-BMP character is reported as its high surrogate
		for (let i = 0; i < jwt.length; i++) {
			const character = jwt.charAt(i);
			if (!regex.test(character)) {
				throw new ParseException(
					`The jwt is invalid because at index ${i} it contains the character ${character} that is neither a '.' nor one permitted in unpadded base64url`,
					0,
				);
			}
		}
	}

	/**
	 * Also see jwtStringToJsonObjectForEnvironment
	 *
	 * Replaces `jwtClaimsSetAsJsonObject(JWT)`: the claims as Nimbus' `JWTClaimsSet.toJSONObject(true)` renders them
	 * (e.g. a single element `aud` array becomes a string, `exp`/`iat`/`nbf` are truncated to whole seconds, a
	 * numeric `sub` becomes a string, duplicate member names are rejected).
	 * @param jwt
	 * @return
	 * @throws ParseException
	 */
	static jwtClaimsSetAsJsonObject(jwt: JWT): JsonObject {
		// This code does multiple conversions to JSON; we could just call 'JsonParser.parseString' here, however
		// that seems to result in the unit test failing as we no longer detect JSON payloads that have the same
		// claim more than once.
		const jsonPayload = jwt.payload;
		if (jsonPayload == null) {
			throw new ParseException("Failed to get JWT payload as a string", 0);
		}

		const claims = claimsSetToJSONObject(nimbusParseJsonObject(jsonPayload));
		return claims;
	}

	/**
	 * Also see jwtStringToJsonObjectForEnvironment
	 * Note: Nimbusds will always remove null values from JWT headers
	 * @param jwt
	 * @return
	 */
	static jwtHeaderAsJsonObject(jwt: JWT): JsonObject {
		const header = structuredClone(jwt.header);
		return header;
	}

	/**
	 * Parses the JWT and returns a JsonObject with value, header and claims entries
	 *
	 * The single-argument form is synchronous. The three-argument form (use if the JWT may be encrypted, e.g an
	 * encrypted request object) is async because decryption uses jose; it returns a Promise.
	 *
	 * @param client Client object containing client_secret, required if symmetric encryption used
	 * @param privateJwksWithEncKeys Key for decryption, if encryption used
	 * @return may return null if decryption fails
	 * @throws ParseException
	 */
	static jwtStringToJsonObjectForEnvironment(jwtAsString: string): JsonObject;
	static jwtStringToJsonObjectForEnvironment(
		jwtAsString: string,
		client: JsonObject | null | undefined,
		privateJwksWithEncKeys: JsonObject | null | undefined,
	): Promise<JsonObject>;
	static jwtStringToJsonObjectForEnvironment(
		jwtAsString: string,
		...rest: [] | [JsonObject | null | undefined, JsonObject | null | undefined]
	): JsonObject | Promise<JsonObject> {
		if (rest.length === 0) {
			const token = JWTUtil.parseJWT(jwtAsString);

			if (token.type === "encrypted") {
				throw new ParseException("EncryptedJWT found, which this test currently doesn't support", 0);
			}
			const header = JWTUtil.jwtHeaderAsJsonObject(token);
			const claims = JWTUtil.jwtClaimsSetAsJsonObject(token);

			return JWTUtil.createJsonObjectForEnvironment(jwtAsString, header, claims);
		}
		return JWTUtil.jwtStringToJsonObjectForEnvironmentMaybeEncrypted(jwtAsString, rest[0], rest[1]);
	}

	private static createJsonObjectForEnvironment(jwtString: string, header: JsonObject, claims: JsonObject): JsonObject {
		const jsonObject: JsonObject = {};
		jsonObject["value"] = jwtString;
		jsonObject["header"] = header;
		jsonObject["claims"] = claims;
		return jsonObject;
	}

	private static async jwtStringToJsonObjectForEnvironmentMaybeEncrypted(
		jwtAsString: string,
		client: JsonObject | null | undefined,
		privateJwksWithEncKeys: JsonObject | null | undefined,
	): Promise<JsonObject> {
		const token = JWTUtil.parseJWT(jwtAsString);
		if (token.type === "encrypted") {
			const encryptedJWT = token;
			const jweHeader = JWTUtil.jwtHeaderAsJsonObject(token);
			const alg = encryptedJWT.header["alg"] as string;
			let decryptionKey: JWK | null = null;
			if (JWE_FAMILY_SYMMETRIC.includes(alg)) {
				if (client == null) {
					throw new ParseException("A client secret is required to decrypt this JWT", 0);
				}
				const client_secret = OIDFJSON.getString(client["client_secret"]);
				if (client_secret == null) {
					throw new ParseException("A client secret is required to decrypt this JWT", 0);
				}
				decryptionKey = JWEUtil.createSymmetricJWKForAlgAndSecret(
					client_secret,
					alg,
					encryptedJWT.header["enc"] as string,
					null,
				);
			} else {
				if (privateJwksWithEncKeys == null) {
					throw new ParseException(
						"No suitable key for decrypting this JWT was provided in the test configuration. A private key of the correct key type with 'use': 'enc' and other matching properties is required.",
						0,
					);
				}
				const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(privateJwksWithEncKeys));
				const kid = encryptedJWT.header["kid"];
				decryptionKey = JWEUtil.selectAsymmetricKeyForEncryption(jwkSet, alg, typeof kid === "string" ? kid : null);
				if (decryptionKey == null) {
					throw new ParseException(
						"No suitable key for decrypting this JWT was provided in the test configuration. A private key of the correct key type with 'use': 'enc' and other matching properties is required.",
						0,
					);
				}
			}
			const decrypter = JWEUtil.createDecrypter(alg, decryptionKey);
			const decryptedJwt = Buffer.from(await decrypter.decrypt(encryptedJWT.serialized)).toString("utf8");
			try {
				JWTUtil.validateJwtContainsOnlyAllowedCharacters(decryptedJwt);
			} catch (e) {
				if (!(e instanceof ParseException)) {
					throw e;
				}
				throw new ParseException("The JWE has been decrypted. " + e.message, 0);
			}
			const out = JWTUtil.jwtStringToJsonObjectForEnvironment(decryptedJwt);
			out["jwe_header"] = jweHeader;
			return out;
		} else {
			const header = JWTUtil.jwtHeaderAsJsonObject(token);
			const claims = JWTUtil.jwtClaimsSetAsJsonObject(token);
			return JWTUtil.createJsonObjectForEnvironment(jwtAsString, header, claims);
		}
	}
}
