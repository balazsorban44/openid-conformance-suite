/**
 * The OP's JWK set (`jwks_uri`) and the checks upstream runs on it before a test starts, plus the generic JWK set
 * validation (upstream sequence/ValidateJwksSequence) used for any JWK set that enters the suite.
 */
import { isDeepStrictEqual } from "node:util";
import { block, condition, soft, type Condition } from "../suite/conditions.ts";
import { HttpError, request } from "../suite/http.ts";
import { parseJwksLenientlyLoggingSkips, ParseException, type Jwks, type JWK } from "../suite/jose.ts";
import {
	findStructurallyInvalidKeys,
	issuesToJson,
	findPrivateOrSymmetricKeyMembers,
	findUnparseableUsableKeys,
	findUnusableKeys,
	parseJWK,
	getRequiredParams,
} from "../suite/jose-jwk.ts";
import type { ServerMetadata } from "./discovery.ts";

/** upstream: condition/client/FetchServerKeys.java */
export async function fetchServerKeys(metadata: ServerMetadata): Promise<Jwks> {
	const c: Condition = condition("FetchServerKeys");
	const jwksUri = metadata.jwks_uri;
	if (!jwksUri) {
		c.failure("Didn't find jwks_uri in the server configuration");
	}
	c.log("Fetching server key", { jwks_uri: jwksUri });
	let res;
	try {
		res = await request(c.name, { url: jwksUri, method: "GET" });
	} catch (e) {
		if (e instanceof HttpError) {
			c.failureFrom("Fetching server keys from " + jwksUri + " failed - " + e.message, e);
		}
		throw e;
	}
	if (res.status >= 400) {
		c.failureFrom(
			"Fetching server keys from " + jwksUri + " failed",
			new HttpError(res.status + " " + res.statusText + ": " + res.body),
		);
	}
	c.log("Found JWK set string", { jwk_string: res.body });
	let parsed: unknown;
	try {
		parsed = JSON.parse(res.body ?? "");
	} catch (e) {
		c.failureFrom("Server JWKs set string is not JSON", e);
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		// Java: getAsJsonObject() throws IllegalStateException (not caught upstream)
		throw new Error("Not a JSON Object: " + res.body);
	}
	const jwks = parsed as Jwks;
	c.success("Found server JWK set", { server_jwks: jwks });
	return jwks;
}

/** upstream: condition/client/CheckServerKeysIsValid.java */
export function checkServerKeysIsValid(jwks: Jwks): void {
	const c: Condition = condition("CheckServerKeysIsValid");
	try {
		parseJwksLenientlyLoggingSkips(c, jwks, "server");
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Unable to parse JWK set", e);
		}
		throw e;
	}
	c.success("Server JWKs is valid", { server_jwks: jwks });
}

/** upstream: condition/common/AbstractCheckForKeyIdinJWKs.java */
function checkForKeyIdInJWKs(c: Condition, jwks: Jwks): void {
	const keys = jwks.keys as unknown;
	if (keys == null) {
		c.failure("keys entry not found in JWKs");
	}
	if (!Array.isArray(keys)) {
		c.failure("keys entry in JWKs is not an array", { keys });
	}
	for (const key of keys) {
		if (typeof key !== "object" || key === null || Array.isArray(key)) {
			c.failure("invalid key in JWKs, not a JSON object", { key });
		}
		const kid = (key as Record<string, unknown>)["kid"];
		if (kid === undefined || String(kid).trim() === "") {
			c.failure("kid not found in key", { key });
		}
	}
	c.success("All keys contain kids");
}

/** upstream: condition/common/CheckForKeyIdInServerJWKs.java */
export function checkForKeyIdInServerJWKs(jwks: Jwks, ...requirements: string[]): void {
	checkForKeyIdInJWKs(condition("CheckForKeyIdInServerJWKs", ...requirements), jwks);
}

/** upstream: condition/common/CheckForKeyIdInClientJWKs.java */
export function checkForKeyIdInClientJWKs(jwks: Jwks, ...requirements: string[]): void {
	checkForKeyIdInJWKs(condition("CheckForKeyIdInClientJWKs", ...requirements), jwks);
}

/**
 * Every signing key of the client's JWKS has a FAPI 2.0 `alg` (PS256, ES256, EdDSA, Ed25519; an EdDSA key on the
 * Ed25519 curve).
 *
 * upstream: condition/common/FAPI2CheckKeyAlgInClientJWKs.java (AbstractFAPI2CheckKeyAlgInClientJWKs)
 */
export function fapi2CheckKeyAlgInClientJWKs(jwks: Jwks, ...requirements: string[]): void {
	const c: Condition = condition("FAPI2CheckKeyAlgInClientJWKs", ...requirements);
	const permitted = ["PS256", "ES256", "EdDSA", "Ed25519"];
	const keys = jwks.keys as unknown;
	if (!Array.isArray(keys)) {
		c.failure("keys array not found in client JWKs");
	}
	for (const key of keys) {
		if (typeof key !== "object" || key === null || Array.isArray(key)) {
			c.failure("invalid key in client JWKs", { key });
		}
		const keyObj = key as Record<string, unknown>;
		if (!Object.hasOwn(keyObj, "alg")) {
			c.failure(
				"'alg' not found in client JWKS provided in the test configuration - this is required to set the request object signing algorithm the conformance suite will use, and should be set to a permitted alg",
				{ key, permitted },
			);
		}
		const use = Object.hasOwn(keyObj, "use") ? String(keyObj["use"]) : null;
		if (use == null || use === "sig") {
			const alg = String(keyObj["alg"]);
			if (!permitted.includes(alg)) {
				c.failure("client jwks contains a signing key with a non-permitted alg", { key: keyObj, permitted });
			}
			if (alg === "EdDSA" || alg === "Ed25519") {
				if (!Object.hasOwn(keyObj, "crv")) {
					c.failure("client jwks contains " + alg + " alg with a missing crv parameter", { key: keyObj });
				}
				if (keyObj["crv"] !== "Ed25519") {
					c.failure("client jwks contains " + alg + " alg with an unsupported curve", { key: keyObj });
				}
			}
		}
	}
	c.success("Keys in client JWKS all have permitted 'alg'", { permitted });
}

/** Nimbus JWK.size(): the modulus bit length of an RSA key, the curve size of an EC key */
function keySize(jwk: JWK): number {
	if (jwk["kty"] === "RSA") {
		const n = Buffer.from(String(jwk["n"]), "base64url");
		let i = 0;
		while (i < n.length && n[i] === 0) {
			i++;
		}
		return i === n.length ? 0 : (n.length - i - 1) * 8 + (32 - Math.clz32(n[i]));
	}
	const curves: Record<string, number> = { "P-256": 256, secp256k1: 256, "P-384": 384, "P-521": 521 };
	return curves[String(jwk["crv"])] ?? 0;
}

/**
 * upstream: condition/as/AbstractEnsureMinimumKeyLength.java (RSA keys at least `minimumKeyLengthRsa` bits, EC keys
 * at least `minimumKeyLengthEc`; keys the JOSE library cannot parse are logged and skipped)
 */
function ensureMinimumKeyLength(
	c: Condition,
	jwks: Jwks | null | undefined,
	jwksKey: string,
	minimumKeyLengthRsa: number,
	minimumKeyLengthEc: number,
): void {
	if (jwks == null) {
		c.failure("Couldn't find " + jwksKey + " in environment");
	}
	let jwkset;
	try {
		// keys the JOSE library cannot parse have no key-length requirement: a recipient ignores keys it cannot use
		// (RFC 7517 section 5), so they are logged and skipped here
		jwkset = parseJwksLenientlyLoggingSkips(c, jwks, jwksKey);
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Failure parsing " + jwksKey, e);
		}
		throw e;
	}
	for (const jwk of jwkset.keys) {
		let minimumLength: number;
		if (jwk["kty"] === "RSA") {
			minimumLength = minimumKeyLengthRsa;
		} else if (jwk["kty"] === "EC") {
			minimumLength = minimumKeyLengthEc;
		} else {
			// No requirement for other key types
			continue;
		}
		const keyLength = keySize(jwk);
		if (keyLength < minimumLength) {
			c.failure("Key found in " + jwksKey + " has fewer bits (is shorter) than required", {
				minimum: minimumLength,
				actual: keyLength,
				key: JSON.stringify(jwk),
			});
		}
	}
	c.success("Validated minimum key lengths for " + jwksKey, { [jwksKey]: jwks });
}

/** upstream: condition/as/FAPI2FinalEnsureMinimumServerKeyLength.java */
export function fapi2FinalEnsureMinimumServerKeyLength(jwks: Jwks | null | undefined, ...requirements: string[]): void {
	ensureMinimumKeyLength(
		condition("FAPI2FinalEnsureMinimumServerKeyLength", ...requirements),
		jwks,
		"server_jwks",
		2048,
		224,
	);
}

/** upstream: condition/as/FAPI2FinalEnsureMinimumClientKeyLength.java */
export function fapi2FinalEnsureMinimumClientKeyLength(jwks: Jwks | null | undefined, ...requirements: string[]): void {
	ensureMinimumKeyLength(
		condition("FAPI2FinalEnsureMinimumClientKeyLength", ...requirements),
		jwks,
		"client_jwks",
		2048,
		224,
	);
}

/** upstream: condition/common/AbstractCheckDistinctKeyIdValueInJWKs.java */
function checkDistinctKeyIdValueInJWKs(c: Condition, jwks: Jwks, envKey: string): void {
	const keys = jwks.keys as unknown;
	if (keys == null) {
		c.failure("keys entry not found in JWKs");
	}
	if (!Array.isArray(keys)) {
		c.failure("keys entry in JWKs is not an array", { keys });
	}
	const seen = new Set<string>();
	for (const key of keys) {
		if (typeof key !== "object" || key === null || Array.isArray(key)) {
			c.failure("invalid key in JWKs, not a JSON object", { key });
		}
		const kid = (key as Record<string, unknown>)["kid"];
		if (kid !== undefined) {
			if (seen.has(String(kid))) {
				c.failure("'kid' value is used more than once in " + envKey, {
					kid_duplicate: kid,
					keys,
					see: "https://bitbucket.org/openid/connect/issues/1127",
				});
			}
			seen.add(String(kid));
		}
	}
	c.success("Distinct 'kid' value in all keys of " + envKey, {
		see: "https://bitbucket.org/openid/connect/issues/1127",
	});
}

/** upstream: condition/common/CheckDistinctKeyIdValueInServerJWKs.java */
export function checkDistinctKeyIdValueInServerJWKs(jwks: Jwks, ...requirements: string[]): void {
	checkDistinctKeyIdValueInJWKs(condition("CheckDistinctKeyIdValueInServerJWKs", ...requirements), jwks, "server_jwks");
}

/** upstream: condition/common/CheckDistinctKeyIdValueInClientJWKs.java */
export function checkDistinctKeyIdValueInClientJWKs(jwks: Jwks, ...requirements: string[]): void {
	checkDistinctKeyIdValueInJWKs(condition("CheckDistinctKeyIdValueInClientJWKs", ...requirements), jwks, "client_jwks");
}

/** One issue a JWK set check found: the first one is named in the message */
type Issues = ReturnType<typeof findStructurallyInvalidKeys>;

function failOnIssues(c: Condition, label: string, issues: Issues, message: (first: Issues[number]) => string): void {
	if (issues.length > 0) {
		c.failure(message(issues[0]), { jwks_source: label, issues: issuesToJson(issues) });
	}
}

/**
 * Validates a JWK set wherever one enters the suite: no private or symmetric key material (unless
 * `allowPrivateKeys`), structurally valid, usable keys parse, unusable keys are a warning. `label` names the set
 * in the messages ("server JWKS").
 *
 * upstream: sequence/ValidateJwksSequence.java with condition/common/MapJwksToValidationLocation.java,
 * EnsureJwksHasNoPrivateOrSymmetricKeyMaterial.java, ValidateJwksStructure.java, ParseUsableJwksKeys.java,
 * WarnOnUnusableJwksKeys.java
 */
export async function validateJwks(
	jwks: Jwks | null | undefined,
	label: string,
	opts: { requirements?: string[]; allowPrivateKeys?: boolean } = {},
): Promise<void> {
	const requirements = opts.requirements ?? [];
	await block("Validate the JWK set in " + label, () => {
		const map: Condition = condition("MapJwksToValidationLocation");
		if (jwks == null) {
			map.failure("Could not find a JWK set to validate for " + label);
		}
		map.success("Selected the JWK set in " + label + " for validation", { jwks });

		if (!opts.allowPrivateKeys) {
			soft(() => {
				const c: Condition = condition("EnsureJwksHasNoPrivateOrSymmetricKeyMaterial", ...requirements);
				failOnIssues(
					c,
					label,
					findPrivateOrSymmetricKeyMembers(jwks),
					(first) =>
						`The JWK set in ${label} contains private or symmetric key material; a published JWK set must contain public keys only. The key at index ${first.index} ${first.detail}.`,
				);
				c.success("The JWK set in " + label + " contains only public key material", { jwks_source: label });
			});
		}
		soft(() => {
			const c: Condition = condition("ValidateJwksStructure", ...requirements);
			if (!Array.isArray(jwks.keys)) {
				c.failure("The JWK set in " + label + " does not contain a 'keys' array", { jwks_source: label, jwks });
			}
			failOnIssues(
				c,
				label,
				findStructurallyInvalidKeys(jwks),
				(first) => `The JWK set in ${label} is structurally invalid. The key at index ${first.index} ${first.detail}.`,
			);
			c.success("The JWK set in " + label + " is structurally valid", { jwks_source: label });
		});
		soft(() => {
			const c: Condition = condition("ParseUsableJwksKeys", ...requirements);
			failOnIssues(
				c,
				label,
				findUnparseableUsableKeys(jwks),
				(first) =>
					`The JWK set in ${label} contains a key that should be usable but the JOSE library cannot parse. The key at index ${first.index} ${first.detail}.`,
			);
			c.success("All usable keys in the JWK set in " + label + " parse successfully", { jwks_source: label });
		});
		soft(() => {
			const c: Condition = condition("WarnOnUnusableJwksKeys", ...requirements);
			const issues = findUnusableKeys(jwks);
			failOnIssues(
				c,
				label,
				issues,
				(first) =>
					`The JWK set in ${label} contains ${issues.length} key(s) that the test suite cannot use (e.g. unsupported key type, curve, or algorithm). The key at index ${first.index} ${first.detail}.`,
			);
			c.success("All keys in the JWK set in " + label + " use a supported key type, curve and algorithm", {
				jwks_source: label,
			});
		}, "warning");
	});
}

/**
 * Fetches the OP's keys and runs upstream's checks on them, in upstream's order (AbstractOIDCCServerTest.configure).
 */
export async function loadServerKeys(metadata: ServerMetadata): Promise<Jwks> {
	const jwks = await fetchServerKeys(metadata);
	soft(() => checkServerKeysIsValid(jwks), "warning");
	await validateJwks(jwks, "server JWKS", { requirements: ["RFC7517-1.1"] });
	soft(() => checkForKeyIdInServerJWKs(jwks, "OIDCC-10.1"));
	soft(() => checkDistinctKeyIdValueInServerJWKs(jwks, "RFC7517-4.5"));
	return jwks;
}

/** upstream: condition/client/TellUserToRotateOpKeys.java */
export function tellUserToRotateOpKeys(): void {
	condition("TellUserToRotateOpKeys").log(
		"Please rotate the keys on the authorization server then press the 'Start' button.",
	);
}

type JsonKey = Record<string, unknown>;

/** Java Set<JsonObject>: no structurally equal duplicates */
function addToSet(set: JsonKey[], o: JsonKey): void {
	if (!set.some((x) => isDeepStrictEqual(x, o))) {
		set.push(o);
	}
}

function setContains(set: JsonKey[], o: JsonKey): boolean {
	return set.some((x) => isDeepStrictEqual(x, o));
}

/**
 * The keys that may sign: `use: sig` or no `use`.
 *
 * upstream: condition/client/AbstractCompareJwks.java filterJsonArrayToSetContainingSigningKeys
 */
function signingKeysOf(jwks: Jwks): JsonKey[] {
	const filtered: JsonKey[] = [];
	for (const key of jwks.keys as unknown as JsonKey[]) {
		// 'use' attribute is completely optional, so we include use: sig or no use claim
		if (key["use"] == null || key["use"] === "sig") {
			addToSet(filtered, key);
		}
	}
	return filtered;
}

/** The public key components, kty and kid of each key (so that key lists can be compared) */
function pubKeysWithKeyId(c: Condition, inputKeys: JsonKey[]): JsonKey[] {
	const out: JsonKey[] = [];
	for (const key of inputKeys) {
		try {
			const jwk = parseJWK(JSON.stringify(key));
			const requiredParamsJson: JsonKey = getRequiredParams(jwk as never);
			requiredParamsJson["kid"] = (jwk["kid"] as string | undefined) ?? null;
			addToSet(out, requiredParamsJson);
		} catch (e) {
			if (e instanceof ParseException) {
				c.failureFrom("Error parsing JWK key", e, { key });
			}
			throw e;
		}
	}
	return out;
}

/**
 * The rotated key set has a signing key the original did not: new kid and new key material.
 *
 * upstream: condition/client/VerifyNewJwksHasNewSigningKey.java (AbstractCompareJwks)
 */
export function verifyNewJwksHasNewSigningKey(originalJwks: Jwks, newJwks: Jwks, ...requirements: string[]): void {
	const c: Condition = condition("VerifyNewJwksHasNewSigningKey", ...requirements);
	// This condition would be a lot easier to write/more robust if we knew which key the OP was & now is using
	// to sign id_tokens - but the python version of this test doesn't do an authentication
	const originalSigningKeys = signingKeysOf(originalJwks);
	const latestSigningKeys = signingKeysOf(newJwks);
	const origSigningPubKeys = pubKeysWithKeyId(c, originalSigningKeys);
	const latestSigningPubKeys = pubKeysWithKeyId(c, latestSigningKeys);
	const keysOnlyInNew = latestSigningPubKeys.filter((k) => !setContains(origSigningPubKeys, k));
	if (keysOnlyInNew.length === 0) {
		c.failure("No new keys with 'use':'sig' (or no 'use') found", {
			original_signing_keys: originalSigningKeys,
			latest_signing_keys: latestSigningKeys,
		});
	}
	// for each new key, verify it is actually new
	for (const newKeyToCheck of keysOnlyInNew) {
		const kid = String(newKeyToCheck["kid"]);
		if (originalSigningKeys.some((mk) => String(mk["kid"]) === kid)) {
			c.failure("One of the new keys uses the same kid as one of the original keys", {
				original_signing_keys: originalSigningKeys,
				latest_signing_keys: latestSigningKeys,
				bad_kid: kid,
			});
		}
		const kty = String(newKeyToCheck["kty"]);
		let field: string;
		switch (kty) {
			case "RSA":
				field = "n";
				break;
			case "EC":
				// it seems sufficient for 'x' to be the same, no need to check 'y'
				field = "x";
				break;
			default:
				return c.failure("unknown key type '" + kty + "' found", { jwk: newKeyToCheck });
		}
		const exponent = String(newKeyToCheck[field]);
		if (originalSigningKeys.some((mk) => mk[field] != null && String(mk[field]) === exponent)) {
			c.failure("One of the new keys uses the same exponent as one of the original keys", {
				original_signing_keys: originalSigningKeys,
				latest_signing_keys: latestSigningKeys,
				["bad_" + field]: exponent,
			});
		}
	}
	c.success("Found new keys", { new_signing_keys: keysOnlyInNew });
}

/** upstream: condition/client/VerifyNewJwksStillHasOldSigningKey.java (AbstractCompareJwks) */
export function verifyNewJwksStillHasOldSigningKey(originalJwks: Jwks, newJwks: Jwks, ...requirements: string[]): void {
	const c: Condition = condition("VerifyNewJwksStillHasOldSigningKey", ...requirements);
	const originalSigningKeys = signingKeysOf(originalJwks);
	const latestSigningKeys = signingKeysOf(newJwks);
	const keysInBoth = originalSigningKeys.filter((k) => setContains(latestSigningKeys, k));
	if (keysInBoth.length === 0) {
		c.failure(
			"None of the previous present keys (with 'use':'sig' or no 'use') are still present. The specification says 'The JWK Set document at the jwks_uri SHOULD retain recently decommissioned signing keys for a reasonable period of time to facilitate a smooth transition.'.",
			{ original_signing_keys: originalSigningKeys, latest_signing_keys: latestSigningKeys },
		);
	}
	c.success("Some keys are in both the old and new JWKS", { signing_keys_in_both: keysInBoth });
}
