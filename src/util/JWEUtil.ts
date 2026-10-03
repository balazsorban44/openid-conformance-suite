import { createHash } from "node:crypto";
import { CompactEncrypt, compactDecrypt, type CompactJWEHeaderParameters } from "jose";
import type { JsonObject } from "../framework/json.ts";
import {
	ENC_FAMILY_AES_CBC_HMAC_SHA,
	ENC_FAMILY_AES_GCM,
	JWE_FAMILY_AES_GCM_KW,
	JWE_FAMILY_AES_KW,
	JWE_FAMILY_ASYMMETRIC,
	JWE_FAMILY_ECDH_ES,
	JWE_FAMILY_RSA,
	JWE_FAMILY_SYMMETRIC,
	JWKUtil,
	nimbusJwkOrder,
	ParseException,
	requireAlgorithmName,
	SkippedJwk,
	type JWK,
	type JWKSet,
} from "./JWKUtil.ts";
import { nimbusParseJWEObject, type JWT } from "./JWTUtil.ts";

/** Port of `com.nimbusds.jose.JOSEException`. */
export class JOSEException extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "JOSEException";
	}
}

/** Port of `com.nimbusds.jose.KeyLengthException`. */
export class KeyLengthException extends JOSEException {
	constructor(message: string) {
		super(message);
		this.name = "KeyLengthException";
	}
}

/** AESEncrypter / AESDecrypter SUPPORTED_ALGORITHMS */
const AES_SUPPORTED_ALGORITHMS: readonly string[] = [...JWE_FAMILY_AES_KW, ...JWE_FAMILY_AES_GCM_KW];
/** DirectEncrypter / DirectDecrypter SUPPORTED_ALGORITHMS */
const DIRECT_SUPPORTED_ALGORITHMS: readonly string[] = ["dir"];
/** RSAEncrypter / RSADecrypter SUPPORTED_ALGORITHMS */
const RSA_SUPPORTED_ALGORITHMS: readonly string[] = JWE_FAMILY_RSA;
/** ECDHEncrypter / ECDHDecrypter / X25519Encrypter / X25519Decrypter SUPPORTED_ALGORITHMS */
const ECDH_SUPPORTED_ALGORITHMS: readonly string[] = JWE_FAMILY_ECDH_ES;

const NIMBUS_KEY_CLASS: Record<string, string> = {
	oct: "OctetSequenceKey",
	RSA: "RSAKey",
	EC: "ECKey",
	OKP: "OctetKeyPair",
};

/** The Java cast `(RSAKey) key` etc: throws (like a ClassCastException) when the key is of another type. */
function castKey(key: JWK, kty: string): JWK {
	if (key["kty"] !== kty) {
		throw new TypeError(
			"class com.nimbusds.jose.jwk." +
				NIMBUS_KEY_CLASS[key["kty"] as string] +
				" cannot be cast to class com.nimbusds.jose.jwk." +
				NIMBUS_KEY_CLASS[kty],
		);
	}
	return key;
}

function octKeyLength(key: JWK): number {
	return Buffer.from(String(key["k"]), "base64url").length;
}

/**
 * Replaces the Nimbus `JWEEncrypter` implementations (`AESEncrypter`, `DirectEncrypter`, `RSAEncrypter`,
 * `ECDHEncrypter`, `X25519Encrypter`). `name` is the Nimbus class name (Java `getClass().getSimpleName()`).
 * `new JWEObject(header, payload).encrypt(encrypter); jweObject.serialize()` becomes
 * `await encrypter.encrypt(header, payload)`.
 */
export class JWEEncrypter {
	readonly name: string;
	readonly key: JWK;

	constructor(name: string, key: JWK) {
		this.name = name;
		this.key = key;
	}

	/**
	 * Encrypts `payload` with the given JWE header (must contain `alg` and `enc`; `apu`/`apv` are passed to jose as
	 * key management parameters) and returns the compact serialization. Async because jose is.
	 * @throws JOSEException / jose errors
	 */
	async encrypt(header: JsonObject, payload: string | Uint8Array): Promise<string> {
		const alg = header["alg"] as string;
		if (this.name === "AESEncrypter") {
			const bits = octKeyLength(this.key) * 8;
			const expected = /^A(\d{3})(?:GCM)?KW$/.exec(alg);
			if (expected && Number(expected[1]) !== bits) {
				throw new KeyLengthException(
					"The Key Encryption Key (KEK) length must be " + expected[1] + " bits for " + alg + " encryption",
				);
			}
		}
		const { apu, apv, ...protectedHeader } = header;
		const keyJwk =
			this.name === "AESEncrypter" || this.name === "DirectEncrypter" ? this.key : JWKUtil.toPublicJWK(this.key);
		const key = await JWKUtil.importKey(keyJwk as JWK, alg);
		const jwe = new CompactEncrypt(typeof payload === "string" ? new TextEncoder().encode(payload) : payload);
		jwe.setProtectedHeader(protectedHeader as CompactJWEHeaderParameters);
		if (apu != null || apv != null) {
			jwe.setKeyManagementParameters({
				...(apu != null ? { apu: Buffer.from(String(apu), "base64url") } : {}),
				...(apv != null ? { apv: Buffer.from(String(apv), "base64url") } : {}),
			});
		}
		return await jwe.encrypt(key);
	}

	getClass(): { getSimpleName(): string } {
		return { getSimpleName: () => this.name };
	}
}

/**
 * Replaces the Nimbus `JWEDecrypter` implementations (`AESDecrypter`, `DirectDecrypter`, `RSADecrypter`,
 * `ECDHDecrypter`, `X25519Decrypter`). `encryptedJWT.decrypt(decrypter); encryptedJWT.getPayload()` becomes
 * `await decrypter.decrypt(compactJwe)` (returns the plaintext bytes). Async because jose is.
 */
export class JWEDecrypter {
	readonly name: string;
	readonly key: JWK;
	readonly algorithm: string;

	constructor(name: string, algorithm: string, key: JWK) {
		this.name = name;
		this.algorithm = algorithm;
		this.key = key;
	}

	/** @throws jose errors (Java: JOSEException) */
	async decrypt(compactJwe: string): Promise<Uint8Array> {
		const { plaintext } = await compactDecrypt(compactJwe, async (header) =>
			JWKUtil.importKey(this.key, header.alg ?? this.algorithm),
		);
		return plaintext;
	}

	getClass(): { getSimpleName(): string } {
		return { getSimpleName: () => this.name };
	}
}

export class JWEUtil {
	/**
	 * Selects the first key in a JWK set JSON object that the recipient of the set could
	 * actually use for encrypting to its owner: the first key that parses as a supported JOSE
	 * key type and is not restricted to signing. The set may contain unusable keys (e.g.
	 * post-quantum keys advertised for crypto agility) that a conformant recipient skips -
	 * RFC 7517 section 5. Each skipped key is recorded in `skippedKeys` - with the reason
	 * it was skipped - so the calling condition can log it into the test log.
	 * Returns null when the set contains no usable key (or has no "keys" array at all).
	 */
	static selectFirstUsableEncKey(jwksJsonObject: JsonObject | null, skippedKeys: SkippedJwk[]): JWK | null {
		if (jwksJsonObject == null) {
			return null;
		}
		let jwkSet: JWKSet;
		try {
			jwkSet = JWKUtil.parseJWKSetLeniently(JSON.stringify(jwksJsonObject), skippedKeys);
		} catch (e) {
			if (!(e instanceof ParseException)) {
				throw e;
			}
			// not a JWK set object with a "keys" array - no usable key in it
			return null;
		}
		for (const jwk of jwkSet.keys) {
			if ("sig" !== jwk["use"]) {
				return jwk;
			}
			skippedKeys.push(new SkippedJwk(structuredClone(jwk), 'key is restricted to signing ("use":"sig")'));
		}
		return null;
	}

	/**
	 * The type of key the given JWE algorithm requires, or null for an algorithm that is neither
	 * RSA nor ECDH-ES based. {@link JWEUtil.selectAsymmetricKeyForEncryption} selects a key by this, so
	 * a caller that has already chosen a key can use this to check the algorithm agrees with it.
	 *
	 * Replaces the Nimbus `KeyType` return value with the `kty` string.
	 */
	static keyTypeForEncryptionAlg(alg: string): "RSA" | "EC" | null {
		if (JWE_FAMILY_RSA.includes(alg)) {
			return "RSA";
		}
		if (JWE_FAMILY_ECDH_ES.includes(alg)) {
			return "EC";
		}
		return null;
	}

	/**
	 * Returns a key that has the correct key type and optionally use=enc,
	 * preferring an exact kid match when one is available from the JWE header.
	 * Only for RSA or EC keys.
	 *
	 * Replaces `selectAsymmetricKeyForEncryption(JWKSet, JWEAlgorithm[, String])`.
	 * @param jwkSet
	 * @param alg
	 * @param kid
	 * @return
	 */
	static selectAsymmetricKeyForEncryption(
		jwkSet: JWKSet | JsonObject | null,
		alg: string,
		kid: string | null = null,
	): JWK | null {
		if (jwkSet == null) {
			return null;
		}

		const keyType = JWEUtil.keyTypeForEncryptionAlg(alg);

		// JWKMatcher.Builder().keyType(keyType).keyUses(KeyUse.ENCRYPTION, null)
		const matches = (jwk: JWK) =>
			(keyType == null || jwk["kty"] === keyType) && (jwk["use"] == null || jwk["use"] === "enc");
		const requiresKidMatch = kid != null && kid.trim().length > 0;
		let currentMatch: JWK | null = null;
		for (const jwk of (jwkSet["keys"] ?? []) as JWK[]) {
			if (matches(jwk)) {
				if (requiresKidMatch) {
					if (kid === jwk["kid"]) {
						return jwk;
					}
					continue;
				}
				if (currentMatch == null) {
					currentMatch = jwk;
				} else {
					if ("enc" !== currentMatch["use"] && "enc" === jwk["use"]) {
						//this is a better match
						currentMatch = jwk;
					}
				}
			}
		}
		return currentMatch;
	}

	/**
	 * https://openid.net/specs/openid-connect-core-1_0.html#Encryption
	 * The symmetric encryption key is derived from the client_secret value by using a left truncated SHA-2
	 * hash of the octets of the UTF-8 representation of the client_secret.
	 * For keys of 256 or fewer bits, SHA-256 is used; for keys of 257-384 bits, SHA-384 is used;
	 * for keys of 385-512 bits, SHA-512 is used. The hash value MUST be left truncated to the appropriate
	 * bit length for the AES key wrapping or direct encryption algorithm used, for instance,
	 * truncating the SHA-256 hash to 128 bits for A128KW.
	 *
	 * @param algorithm
	 * @param inputString
	 * @return the key bytes
	 */
	static deriveEncryptionKey(algorithm: string, inputString: string): Buffer {
		let targetLength = 16;
		const digestAlgorithm = "sha256";

		const matchedNumber = JWEUtil.getKeyLengthFromAlg(algorithm);
		if (matchedNumber == null) {
			throw new Error("Unable to parse key bit length from algorithm " + algorithm);
		}

		switch (matchedNumber) {
			case "128":
				targetLength = 16;
				break;
			case "192":
				targetLength = 24;
				break;
			case "256":
				targetLength = 32;
				break;
			default:
				throw new Error("Unexpected algorithm:" + algorithm);
		}

		const digest = createHash(digestAlgorithm).update(Buffer.from(inputString, "utf8")).digest();

		const keyBytes = Buffer.alloc(targetLength);
		digest.copy(keyBytes, 0, 0, targetLength);

		return keyBytes;
	}

	private static getKeyLengthFromAlg(algorithm: string): string | null {
		// Regexes and logic from Filip's openid-client, "secretForAlg(alg)" in client.js
		let matcher = /^A(\d{3})(?:GCM)?KW$/.exec(algorithm);
		if (matcher) {
			return matcher[1];
		}

		matcher = /^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.exec(algorithm);
		if (matcher) {
			return matcher[2] != null ? matcher[2] : matcher[1];
		}

		return null;
	}

	/**
	 * AES or "dir" only
	 *
	 * Replaces `createSymmetricJWKForAlgAndSecret(String, JWEAlgorithm, EncryptionMethod, String)` returning a
	 * Nimbus OctetSequenceKey: returns the JSON oct JWK (`kty`, `use`, `alg`, `kid`, `k`).
	 * @param secret
	 * @param algorithm
	 * @param encMethod
	 * @param keyId
	 * @return
	 * @throws KeyLengthException
	 */
	static createSymmetricJWKForAlgAndSecret(
		secret: string,
		algorithm: string,
		encMethod: string | null,
		keyId: string | null,
	): JWK | null {
		let key: JWK | null = null;
		const build = (secretBytes: Buffer): JWK => {
			if (secretBytes.length === 0) {
				throw new KeyLengthException("The key must have a positive length");
			}
			const builder: JsonObject = { kty: "oct", use: "enc", alg: algorithm };
			if (keyId != null) {
				builder["kid"] = keyId;
			}
			builder["k"] = secretBytes.toString("base64url");
			return nimbusJwkOrder(builder);
		};
		if (JWE_FAMILY_AES_GCM_KW.includes(algorithm) || JWE_FAMILY_AES_KW.includes(algorithm)) {
			const secretBytes = JWEUtil.deriveEncryptionKey(algorithm, secret);
			key = build(secretBytes);
		} else if ("dir" === algorithm) {
			if (encMethod == null) {
				throw new TypeError('Cannot invoke "com.nimbusds.jose.EncryptionMethod.getName()" because "encMethod" is null');
			}
			const secretBytes = JWEUtil.deriveEncryptionKey(encMethod, secret);
			key = build(secretBytes);
		}
		return key;
	}

	/**
	 * may return null when it doesn't know how to handle the key
	 * @param key
	 * @return AESEncrypter or DirectEncrypter or RSAEncrypter or ECDHEncrypter (as a {@link JWEEncrypter})
	 * @throws JOSEException
	 */
	static createEncrypter(key: JWK | null): JWEEncrypter | null {
		if (key == null) {
			return null;
		}
		const kty = key["kty"];
		if ("oct" === kty) {
			if (AES_SUPPORTED_ALGORITHMS.includes(key["alg"] as string)) {
				JWEUtil.checkAesKeyLength(key);
				const aesEncrypter = new JWEEncrypter("AESEncrypter", key);
				return aesEncrypter;
			} else if (DIRECT_SUPPORTED_ALGORITHMS.includes(key["alg"] as string)) {
				JWEUtil.checkDirectKeyLength(key);
				const directEncrypter = new JWEEncrypter("DirectEncrypter", key);
				return directEncrypter;
			} else {
				throw new Error("Unexpected algorithm:" + (key["alg"] ?? null));
			}
		} else if ("RSA" === kty) {
			const rsaEncrypter = new JWEEncrypter("RSAEncrypter", key);
			return rsaEncrypter;
		} else if ("EC" === kty) {
			const ecdhEncrypter = new JWEEncrypter("ECDHEncrypter", key);
			return ecdhEncrypter;
		} else if ("OKP" === kty) {
			const octetKeyPair = key;
			if ("Ed25519" === octetKeyPair["crv"]) {
				// UPSTREAM: Nimbus' X25519Encrypter only accepts crv=X25519, so this branch always fails in Java
				throw new JOSEException("X25519Encrypter only supports OctetKeyPairs with crv=X25519");
			}
		}
		throw new Error("Unexpected key type:" + kty);
	}

	private static checkAesKeyLength(key: JWK): void {
		if (![16, 24, 32].includes(octKeyLength(key))) {
			throw new KeyLengthException(
				"The Key Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes)",
			);
		}
	}

	private static checkDirectKeyLength(key: JWK): void {
		if (![16, 24, 32, 48, 64].includes(octKeyLength(key))) {
			throw new KeyLengthException(
				"The Content Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384 bits (48 bytes) or 512 bites (64 bytes)",
			);
		}
	}

	/**
	 * Java overloads `createDecrypter(JWK)`, `createDecrypter(String, JWK)` and `createDecrypter(Algorithm, JWK)`:
	 * pass either just the key (its `alg` is used) or the algorithm name and the key.
	 *
	 * @return AESDecrypter or DirectDecrypter or RSADecrypter or ECDHDecrypter or X25519Decrypter (as a
	 *   {@link JWEDecrypter})
	 * @throws JOSEException
	 */
	static createDecrypter(key: JWK): JWEDecrypter;
	static createDecrypter(algorithm: string, key: JWK | null): JWEDecrypter;
	static createDecrypter(algorithmOrKey: string | JWK, maybeKey?: JWK | null): JWEDecrypter {
		let algorithm: string;
		let key: JWK | null;
		if (typeof algorithmOrKey === "string") {
			algorithm = algorithmOrKey;
			key = maybeKey ?? null;
		} else {
			key = algorithmOrKey;
			const alg = key["alg"];
			if (alg == null) {
				throw new Error("No 'alg' in key: " + JSON.stringify(key));
			}
			algorithm = alg as string;
		}
		if (key == null) {
			throw new Error("Private key is required for " + algorithm);
		}
		if (AES_SUPPORTED_ALGORITHMS.includes(algorithm)) {
			JWEUtil.checkAesKeyLength(castKey(key, "oct"));
			const decrypter = new JWEDecrypter("AESDecrypter", algorithm, key);
			return decrypter;
		} else if (DIRECT_SUPPORTED_ALGORITHMS.includes(algorithm)) {
			JWEUtil.checkDirectKeyLength(castKey(key, "oct"));
			const directDecrypter = new JWEDecrypter("DirectDecrypter", algorithm, key);
			return directDecrypter;
		} else if (RSA_SUPPORTED_ALGORITHMS.includes(algorithm)) {
			const rsaDecrypter = new JWEDecrypter("RSADecrypter", algorithm, castKey(key, "RSA"));
			return rsaDecrypter;
		} else if (ECDH_SUPPORTED_ALGORITHMS.includes(algorithm)) {
			const ecdhDecrypter = new JWEDecrypter("ECDHDecrypter", algorithm, castKey(key, "EC"));
			return ecdhDecrypter;
		} else {
			// X25519Decrypter.SUPPORTED_ALGORITHMS is the ECDH-ES family, already handled above
			throw new Error("Unknown algorithm '" + algorithm + "' for key: " + JSON.stringify(key));
		}
	}

	static isAsymmetricJWEAlgorithm(algorithmName: string | null | undefined): boolean {
		algorithmName = requireAlgorithmName(algorithmName);
		return JWE_FAMILY_ASYMMETRIC.includes(algorithmName);
	}

	static isSymmetricJWEAlgorithm(algorithmName: string | null | undefined): boolean {
		algorithmName = requireAlgorithmName(algorithmName);
		return JWE_FAMILY_SYMMETRIC.includes(algorithmName);
	}

	/**
	 * Checks if alg is a JWE algorithm registered in either the asymmetric or
	 * symmetric Nimbus JWEAlgorithm families. Used to validate published
	 * `alg_values_supported` metadata entries.
	 */
	static isValidJWEAlgorithm(algorithmName: string | null | undefined): boolean {
		algorithmName = requireAlgorithmName(algorithmName);
		return JWE_FAMILY_ASYMMETRIC.includes(algorithmName) || JWE_FAMILY_SYMMETRIC.includes(algorithmName);
	}

	/**
	 * Returns the names of asymmetric JWE algorithms only — the set of
	 * `alg` values that can be used in flows where the recipient publishes
	 * its public key (e.g. OID4VCI credential response encryption).
	 */
	static validAsymmetricJWEAlgorithms(): string[] {
		return [...JWE_FAMILY_ASYMMETRIC];
	}

	/**
	 * Checks if `enc` names a JWA content encryption algorithm registered in
	 * the IANA JOSE registry. Restricted to the RFC 7518 §5 set
	 * (`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`,
	 * `A128GCM`, `A192GCM`, `A256GCM`); other Nimbus-defined
	 * extras (e.g. deprecated aliases, `XC20P`) are intentionally excluded
	 * because they are not in the JWA registry and would not interoperate.
	 */
	static isValidEncryptionMethod(enc: string | null | undefined): boolean {
		enc = requireAlgorithmName(enc);
		return ENC_FAMILY_AES_CBC_HMAC_SHA.includes(enc) || ENC_FAMILY_AES_GCM.includes(enc);
	}

	static validEncryptionMethods(): string[] {
		return [...ENC_FAMILY_AES_CBC_HMAC_SHA, ...ENC_FAMILY_AES_GCM];
	}

	/**
	 * Returns the header of an encrypted or parsed JWE (replaces Nimbus `JWEObject`) as a JsonObject.
	 * Mirrors `JWTUtil.jwtHeaderAsJsonObject` but for bare JWEs. Nimbus always
	 * strips null-valued header parameters.
	 *
	 * @param jweObject the JWE as parsed by {@link JWEUtil.jweStringToJsonObjectForEnvironment}'s parser or
	 *                  `JWTUtil.parseJWT`, or a compact JWE string
	 * @return the JWE header as a JsonObject
	 * @throws ParseException when given a string that cannot be parsed
	 */
	static jweHeaderAsJsonObject(jweObject: JWT | string): JsonObject {
		const jwe = typeof jweObject === "string" ? nimbusParseJWEObject(jweObject) : jweObject;
		return structuredClone(jwe.header);
	}

	/**
	 * Parses a compact-serialized JWE whose payload is a plain JSON object and returns a
	 * log-friendly JsonObject with the same field names used by
	 * `JWTUtil.jwtStringToJsonObjectForEnvironment(String, JsonObject, JsonObject)`
	 * so test logs render JWT-wrapped and JSON-wrapped encrypted content the same way:
	 *
	 * <ul>
	 *   <li>`value` — plaintext serialized as a string (mirroring the JWT variant
	 *       where `value` is the decrypted inner JWT compact string, not the outer
	 *       JWE)</li>
	 *   <li>`claims` — plaintext parsed as a JsonObject</li>
	 *   <li>`jwe_header` — header of the outer JWE</li>
	 * </ul>
	 *
	 * <p>Unlike the JWT variant, there is no `header` entry because OID4VCI JWEs
	 * wrap a plain JSON body rather than a nested signed JWT — there is no inner JWT
	 * header to report.
	 *
	 * <p>This method does not attempt to decrypt the JWE — the caller is expected to
	 * already have the plaintext and passes it as `payload`.
	 *
	 * @param jweAsString compact serialization of the JWE
	 * @param payload     the plaintext JSON payload
	 * @return JsonObject with `value`, `claims` and `jwe_header` entries
	 * @throws ParseException if the compact JWE cannot be parsed
	 */
	static jweStringToJsonObjectForEnvironment(jweAsString: string, payload: JsonObject): JsonObject {
		const jweObject = nimbusParseJWEObject(jweAsString);
		const out: JsonObject = {};
		out["value"] = JSON.stringify(payload);
		out["claims"] = payload;
		out["jwe_header"] = JWEUtil.jweHeaderAsJsonObject(jweObject);
		return out;
	}
}
