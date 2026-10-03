/**
 * Nimbus compact serialization parsing (`JWTParser.parse`, `SignedJWT.parse`, `JWEObject.parse`,
 * `JOSEObject.split`, `PlainHeader/JWSHeader/JWEHeader.parse`) and `JWTClaimsSet.parse` + `toJSONObject`, with
 * Nimbus' error messages and JSON member order; then the functions of upstream's util/JWTUtil (a JWT as upstream
 * stores it: value, header, claims, decrypting a JWE first).
 */
import {
	type JsonObject,
	type JsonValue,
	JavaHashMap,
	nimbusGetBoolean,
	nimbusGetJSONArray,
	nimbusGetJSONObject,
	nimbusGetLong,
	nimbusGetString,
	nimbusGetStringList,
	nimbusGetURI,
	nimbusParseJsonObject,
	getString,
	javaHashMapOf,
} from "./json.ts";
import { ParseException } from "./errors.ts";
import { isPrivate, parseJWK, parseJWKSet, type JWK } from "./jose-jwk.ts";
import { createSymmetricJWKForAlgAndSecret, selectAsymmetricKeyForEncryption, createDecrypter } from "./jose-jwe.ts";
import { JWE_FAMILY_SYMMETRIC } from "./jose-algorithms.ts";

/**
 * A parsed (not verified, not decrypted) compact JOSE object. Replaces the Nimbus `JWT` interface and its
 * implementations `PlainJWT` (`type: "plain"`), `SignedJWT` (`type: "signed"`) and `EncryptedJWT`
 * (`type: "encrypted"`), as returned by `JWTParser.parse` / `parseJWT`, and `JWEObject` as returned by
 * `JWEObject.parse`.
 *
 * - `jwt instanceof EncryptedJWT` -> `jwt.type === "encrypted"`
 * - `jwt.getHeader().toJSONObject()` -> `jwt.header` (or `jwtHeaderAsJsonObject(jwt)`)
 * - `jwt.getHeader().getAlgorithm().getName()` -> `jwt.header["alg"]`
 * - `jwt.getJWTClaimsSet()` -> `jwtClaimsSetAsJsonObject(jwt)`
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

	// Header.toJSONObject(): the custom parameters (a HashMap) are put first into a HashMap, then the registered ones
	const custom = javaHashMapOf(Object.entries(json).filter(([name]) => !registered.includes(name)));
	const out: JsonObject = {};
	const finish = (): JsonObject => {
		const o = new JavaHashMap();
		o.putAll(custom.entries());
		for (const [k, v] of Object.entries(out)) {
			o.put(k, v);
		}
		return o.toJsonObject();
	};
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
		return finish();
	}
	putString("jku", nimbusGetURI(json, "jku"));
	const jwkJson = nimbusGetJSONObject(json, "jwk");
	if (jwkJson != null) {
		const jwk = parseJWK(jwkJson);
		if (isPrivate(jwk)) {
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
		return finish();
	}
	out["enc"] = enc;
	const epkJson = "epk" in json ? nimbusGetJSONObject(json, "epk") : null;
	if (epkJson != null) {
		const epk = parseJWK(epkJson);
		if (isPrivate(epk)) {
			// IllegalArgumentException in Java: not wrapped into a ParseException
			throw new Error("Ephemeral public key should not be a private key");
		}
		out["epk"] = epk;
	}
	putString("zip", nimbusGetString(json, "zip"));
	putString("apu", nimbusGetString(json, "apu"));
	putString("apv", nimbusGetString(json, "apv"));
	putString("p2s", nimbusGetString(json, "p2s"));
	if ("p2c" in json) {
		const p2c = nimbusGetLong(json, "p2c");
		if (p2c < 0) {
			// IllegalArgumentException in Java: not wrapped into a ParseException
			throw new Error("The PBES2 count parameter must not be negative");
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
	return finish();
}

function parseHeaderPart(part: string, kind: "plain" | "signed" | "encrypted"): JsonObject {
	return parseHeader(nimbusParseJsonObject(decodeToString(part), MAX_HEADER_STRING_LENGTH), kind);
}

/** Nimbus PlainJWT.parse / SignedJWT.parse / EncryptedJWT.parse */
export function parseJOSEObject(s: string, kind: "plain" | "signed" | "encrypted"): JWT {
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
export function jwtParserParse(s: string): JWT {
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
 * Nimbus `JWEObject.parse(String)`.
 * @throws ParseException
 */
export function parseJWEObject(s: string): JWT {
	return parseJOSEObject(s, "encrypted");
}

/** Nimbus JWTClaimsSet.parse(Map) followed by toJSONObject(true) */
export function claimsSetToJSONObject(json: JsonObject): JsonObject {
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

	const o = new JavaHashMap();
	for (const [key, value] of claims) {
		if (dateClaims.has(key)) {
			// Transform dates to Unix timestamps
			o.put(key, value);
		} else if (key === "aud") {
			// Serialise single audience list and string
			const audList = value as string[] | null;
			if (audList != null && audList.length > 0) {
				if (audList.length === 1) {
					o.put("aud", audList[0]);
				} else {
					o.put("aud", [...audList]);
				}
			} else {
				o.put("aud", null);
			}
		} else {
			o.put(key, value);
		}
	}
	return o.toJsonObject();
}

/**
 * Nimbus `SignedJWT.parse(String)`: `JOSEObject.split`, exactly three parts, then the `JWSObject` constructor
 * (`JWSHeader.parse` wrapped as "Invalid JWS header: ...", "The signature must not be empty").
 *
 * Unified from four copies (AbstractVerifyJwsSignature, ValidateRequestObjectSignature,
 * ValidateClientAssertionSignatureWithHMACAlgorithm, EnsureClientAssertionSignatureAlgorithmMatchesRegistered; plus
 * an inline variant in ValidateUserInfoSigningAlgIsRS256). They agreed with each other, but all went through the
 * `JWTParser.parse` port (`parseJWT`) and then rejected what was not a JWS, which differs from
 * `SignedJWT.parse` - the method every one of the Java conditions calls - for invalid input. Kept: SignedJWT.parse,
 * so the conditions now log the messages the Java conditions log:
 *
 * - a character outside base64url and '.' (or surrounding whitespace): no error from the parse, where JWTUtil's
 *   "The jwt is invalid because at index ..." check fired (Nimbus' split trims and Base64URL decoding skips such
 *   characters; the signature check then fails instead);
 * - no dot: "Invalid serialized unsecured/JWS/JWE object: Missing part delimiters" (was "Invalid JWT serialization:
 *   Missing dot delimiter(s)"); one dot: "... Missing second delimiter"; more than four dots: "... Too many part
 *   delimiters" (both were "Invalid unsecured/JWS/JWE header: Invalid JSON object");
 * - an undecodable / non-JSON header or one without "alg": "Invalid JWS header: ..." (was
 *   "Invalid unsecured/JWS/JWE header: ..." or the bare message);
 * - `alg: none` with a non-empty third part, or three parts with an `enc` header: "Invalid JWS header: Not a JWS
 *   header" (was the PlainJWT / EncryptedJWT parse error);
 * - ValidateUserInfoSigningAlgIsRS256 reported "Not a JWS header" for any non-JWS; SignedJWT.parse says "Unexpected
 *   number of Base64URL parts, must be three" for a JWE and "Invalid JWS header: Not a JWS header" for alg none.
 *
 * For a valid JWS, a five part JWE, a three part `alg: none` JWT and an empty signature the result and the messages
 * are unchanged.
 *
 * @throws ParseException
 */
export function parseSignedJWT(s: string): JWT {
	return parseJOSEObject(s, "signed");
}

/**
 * Nimbus `JWTClaimsSet.parse(claims.toString())` followed by `toJSONObject(includeNullValues)`: validates the
 * registered claims as Nimbus does and returns them as Nimbus serializes them (without null valued claims unless
 * `includeNullValues`, as `JWTClaimsSet.toPayload()` does). (Was defined in AbstractSignJWT.)
 *
 * @throws ParseException
 */
export function parseClaimsSet(claims: JsonObject, includeNullValues = false): JsonObject {
	const parsed = claimsSetToJSONObject(nimbusParseJsonObject(JSON.stringify(claims)));
	if (includeNullValues) {
		return parsed;
	}
	const out: JsonObject = {};
	for (const [k, v] of Object.entries(parsed)) {
		if (v !== null) {
			out[k] = v;
		}
	}
	return out;
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
 *
 * upstream: util/JWTUtil.java
 */
export function parseJWT(jwtAsString: string): JWT {
	validateJwtContainsOnlyAllowedCharacters(jwtAsString);
	const jwt = jwtParserParse(jwtAsString);
	return jwt;
}

/** @throws ParseException (upstream: util/JWTUtil.java) */
export function validateJwtContainsOnlyAllowedCharacters(jwt: string): void {
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
 *
 * upstream: util/JWTUtil.java
 */
export function jwtClaimsSetAsJsonObject(jwt: JWT): JsonObject {
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
 *
 * upstream: util/JWTUtil.java
 */
export function jwtHeaderAsJsonObject(jwt: JWT): JsonObject {
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
 *
 * upstream: util/JWTUtil.java
 */
export function jwtStringToJsonObjectForEnvironment(jwtAsString: string): JsonObject;
export function jwtStringToJsonObjectForEnvironment(
	jwtAsString: string,
	client: JsonObject | null | undefined,
	privateJwksWithEncKeys: JsonObject | null | undefined,
): Promise<JsonObject>;
export function jwtStringToJsonObjectForEnvironment(
	jwtAsString: string,
	...rest: [] | [JsonObject | null | undefined, JsonObject | null | undefined]
): JsonObject | Promise<JsonObject> {
	if (rest.length === 0) {
		const token = parseJWT(jwtAsString);

		if (token.type === "encrypted") {
			throw new ParseException("EncryptedJWT found, which this test currently doesn't support", 0);
		}
		const header = jwtHeaderAsJsonObject(token);
		const claims = jwtClaimsSetAsJsonObject(token);

		return createJsonObjectForEnvironment(jwtAsString, header, claims);
	}
	return jwtStringToJsonObjectForEnvironmentMaybeEncrypted(jwtAsString, rest[0], rest[1]);
}

function createJsonObjectForEnvironment(jwtString: string, header: JsonObject, claims: JsonObject): JsonObject {
	const jsonObject: JsonObject = {};
	jsonObject["value"] = jwtString;
	jsonObject["header"] = header;
	jsonObject["claims"] = claims;
	return jsonObject;
}

async function jwtStringToJsonObjectForEnvironmentMaybeEncrypted(
	jwtAsString: string,
	client: JsonObject | null | undefined,
	privateJwksWithEncKeys: JsonObject | null | undefined,
): Promise<JsonObject> {
	const token = parseJWT(jwtAsString);
	if (token.type === "encrypted") {
		const encryptedJWT = token;
		const jweHeader = jwtHeaderAsJsonObject(token);
		const alg = encryptedJWT.header["alg"] as string;
		let decryptionKey: JWK | null = null;
		if (JWE_FAMILY_SYMMETRIC.includes(alg)) {
			if (client == null) {
				throw new ParseException("A client secret is required to decrypt this JWT", 0);
			}
			const client_secret = getString(client["client_secret"]);
			if (client_secret == null) {
				throw new ParseException("A client secret is required to decrypt this JWT", 0);
			}
			decryptionKey = createSymmetricJWKForAlgAndSecret(client_secret, alg, encryptedJWT.header["enc"] as string, null);
		} else {
			if (privateJwksWithEncKeys == null) {
				throw new ParseException(
					"No suitable key for decrypting this JWT was provided in the test configuration. A private key of the correct key type with 'use': 'enc' and other matching properties is required.",
					0,
				);
			}
			const jwkSet = parseJWKSet(JSON.stringify(privateJwksWithEncKeys));
			const kid = encryptedJWT.header["kid"];
			decryptionKey = selectAsymmetricKeyForEncryption(jwkSet, alg, typeof kid === "string" ? kid : null);
			if (decryptionKey == null) {
				throw new ParseException(
					"No suitable key for decrypting this JWT was provided in the test configuration. A private key of the correct key type with 'use': 'enc' and other matching properties is required.",
					0,
				);
			}
		}
		const decrypter = createDecrypter(alg, decryptionKey);
		const decryptedJwt = Buffer.from(await decrypter.decrypt(encryptedJWT.serialized)).toString("utf8");
		try {
			validateJwtContainsOnlyAllowedCharacters(decryptedJwt);
		} catch (e) {
			if (!(e instanceof ParseException)) {
				throw e;
			}
			throw new ParseException("The JWE has been decrypted. " + e.message, 0);
		}
		const out = jwtStringToJsonObjectForEnvironment(decryptedJwt);
		out["jwe_header"] = jweHeader;
		return out;
	} else {
		const header = jwtHeaderAsJsonObject(token);
		const claims = jwtClaimsSetAsJsonObject(token);
		return createJsonObjectForEnvironment(jwtAsString, header, claims);
	}
}
