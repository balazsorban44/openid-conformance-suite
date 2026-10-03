import type { CryptoKey } from "jose";
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
import {
	JWE_FAMILY_ASYMMETRIC,
	JWE_FAMILY_SYMMETRIC,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_SIGNATURE,
} from "./nimbus/algorithms.ts";
import { ParseException } from "./nimbus/errors.ts";
import * as nimbusJwk from "./nimbus/jwk.ts";
import {
	EC_SUPPORTED_CURVES,
	jwkSetToJSONObject,
	OKP_SUPPORTED_CURVES,
	parseCurve,
	type JWK,
	type JWKSet,
} from "./nimbus/jwk.ts";

// The Nimbus emulation lives in ./nimbus/; re-exported here for the ported code that imports it from JWKUtil.
export type { JWK, JWKSet } from "./nimbus/jwk.ts";
export { ParseException } from "./nimbus/errors.ts";
export {
	ENC_FAMILY_AES_CBC_HMAC_SHA,
	ENC_FAMILY_AES_GCM,
	JWE_FAMILY_AES_GCM_KW,
	JWE_FAMILY_AES_KW,
	JWE_FAMILY_ASYMMETRIC,
	JWE_FAMILY_ECDH_1PU,
	JWE_FAMILY_ECDH_ES,
	JWE_FAMILY_PBES2,
	JWE_FAMILY_RSA,
	JWE_FAMILY_SYMMETRIC,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	JWS_FAMILY_SIGNATURE,
} from "./nimbus/algorithms.ts";

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

export class JWKUtil {
	/** Alias so `new JWKUtil.SkippedJwk(...)` works as in Java; the type is the exported {@link SkippedJwk}. */
	static readonly SkippedJwk = SkippedJwk;
	/** Alias so `new JWKUtil.JwkIssue(...)` works as in Java; the type is the exported {@link JwkIssue}. */
	static readonly JwkIssue = JwkIssue;

	/**
	 * Nimbus `JWKSet.parse(String)` (implemented in nimbus/jwk.ts): returns the JSON form of the parsed set.
	 * Also accepts an already parsed JSON object.
	 *
	 * @throws ParseException
	 */
	static parseJWKSet(jwksString: string | JsonObject): JWKSet {
		const jwkSet = nimbusJwk.parseJWKSet(jwksString);
		return jwkSet;
	}

	/**
	 * Not in upstream: Nimbus `JWK.parse(String)` / `JWK.parse(Map)` (implemented in nimbus/jwk.ts), kept here for
	 * the conditions that call `JWKUtil.parseJWK`.
	 *
	 * @throws ParseException
	 */
	static parseJWK(jwk: string | JsonObject): JWK {
		return nimbusJwk.parseJWK(jwk);
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

	private static unsupportedCurve(key: JsonObject, supported: readonly string[]): string | null {
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
		return jwkSetToJSONObject(jwks, true);
	}

	/** Replaces `jwks.toJSONObject(false)` on a Nimbus JWKSet: all keys including private members. */
	static getPrivateJwksAsJsonObject(jwks: JsonObject): JsonObject {
		return jwkSetToJSONObject(jwks, false);
	}

	/** Not in upstream: Nimbus `JWK.toPublicJWK()` (implemented in nimbus/jwk.ts). */
	static toPublicJWK(jwk: JsonObject): JWK | null {
		return nimbusJwk.toPublicJWK(jwk);
	}

	/** Not in upstream: Nimbus `JWK.isPrivate()` (implemented in nimbus/jwk.ts). */
	static isPrivate(jwk: JsonObject): boolean {
		return nimbusJwk.isPrivate(jwk);
	}

	/** Not in upstream: a JSON JWK as a jose key, replacing Nimbus `toRSAPublicKey()` etc. (see nimbus/jwk.ts). */
	static async importKey(jwk: JsonObject, alg?: string): Promise<CryptoKey | Uint8Array> {
		return await nimbusJwk.importKey(jwk, alg);
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
			return jwkSetToJSONObject(fullSet, true);
		} catch (e) {
			throw new Error("Failed to convert JWKS to public version", { cause: e });
		}
	}
}
