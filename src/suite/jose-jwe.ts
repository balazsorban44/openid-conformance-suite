/**
 * JWE decryption as upstream does it: the Nimbus `JWEDecrypter` implementations on top of jose (`AESDecrypter`,
 * `DirectDecrypter`, `RSADecrypter`, `ECDHDecrypter`), their `SUPPORTED_ALGORITHMS` and key length checks, the Java
 * casts between the Nimbus JWK classes, and the functions of upstream's util/JWEUtil (key selection and the
 * client_secret derived keys of OIDC Core 10.2).
 */
import { createHash } from "node:crypto";
import { compactDecrypt } from "jose";
import { KeyLengthException } from "./errors.ts";
import {
	JWE_FAMILY_AES_GCM_KW,
	JWE_FAMILY_AES_KW,
	JWE_FAMILY_ASYMMETRIC,
	JWE_FAMILY_ECDH_ES,
	JWE_FAMILY_RSA,
	JWE_FAMILY_SYMMETRIC,
	requireAlgorithmName,
} from "./jose-algorithms.ts";
import { importKey, nimbusJwkOrder, type JWK, type JWKSet } from "./jose-jwk.ts";
import type { JsonObject } from "./json.ts";

/** AESEncrypter / AESDecrypter SUPPORTED_ALGORITHMS */
export const AES_SUPPORTED_ALGORITHMS: readonly string[] = [...JWE_FAMILY_AES_KW, ...JWE_FAMILY_AES_GCM_KW];
/** DirectEncrypter / DirectDecrypter SUPPORTED_ALGORITHMS */
export const DIRECT_SUPPORTED_ALGORITHMS: readonly string[] = ["dir"];
/** RSAEncrypter / RSADecrypter SUPPORTED_ALGORITHMS */
export const RSA_SUPPORTED_ALGORITHMS: readonly string[] = JWE_FAMILY_RSA;
/** ECDHEncrypter / ECDHDecrypter / X25519Encrypter / X25519Decrypter SUPPORTED_ALGORITHMS */
export const ECDH_SUPPORTED_ALGORITHMS: readonly string[] = JWE_FAMILY_ECDH_ES;

const NIMBUS_KEY_CLASS: Record<string, string> = {
	oct: "OctetSequenceKey",
	RSA: "RSAKey",
	EC: "ECKey",
	OKP: "OctetKeyPair",
};

/** The Java cast `(RSAKey) key` etc: throws (like a ClassCastException) when the key is of another type. */
export function castKey(key: JWK, kty: string): JWK {
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

/** The key length check of the Nimbus `AESEncrypter` / `AESDecrypter` constructors. @throws KeyLengthException */
export function checkAesKeyLength(key: JWK): void {
	if (![16, 24, 32].includes(octKeyLength(key))) {
		throw new KeyLengthException(
			"The Key Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes)",
		);
	}
}

/** The key length check of the Nimbus `DirectEncrypter` / `DirectDecrypter` constructors. @throws KeyLengthException */
export function checkDirectKeyLength(key: JWK): void {
	if (![16, 24, 32, 48, 64].includes(octKeyLength(key))) {
		throw new KeyLengthException(
			"The Content Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32 bytes), 384 bits (48 bytes) or 512 bites (64 bytes)",
		);
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
			importKey(this.key, header.alg ?? this.algorithm),
		);
		return plaintext;
	}

	getClass(): { getSimpleName(): string } {
		return { getSimpleName: () => this.name };
	}
}

/**
 * The type of key the given JWE algorithm requires, or null for an algorithm that is neither
 * RSA nor ECDH-ES based. {@link selectAsymmetricKeyForEncryption} selects a key by this, so
 * a caller that has already chosen a key can use this to check the algorithm agrees with it.
 *
 * Replaces the Nimbus `KeyType` return value with the `kty` string.
 *
 * upstream: util/JWEUtil.java
 */
export function keyTypeForEncryptionAlg(alg: string): "RSA" | "EC" | null {
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
 *
 * upstream: util/JWEUtil.java
 */
export function selectAsymmetricKeyForEncryption(
	jwkSet: JWKSet | JsonObject | null,
	alg: string,
	kid: string | null = null,
): JWK | null {
	if (jwkSet == null) {
		return null;
	}

	const keyType = keyTypeForEncryptionAlg(alg);

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
 *
 * upstream: util/JWEUtil.java
 */
export function deriveEncryptionKey(algorithm: string, inputString: string): Buffer {
	let targetLength = 16;
	const digestAlgorithm = "sha256";

	const matchedNumber = getKeyLengthFromAlg(algorithm);
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

function getKeyLengthFromAlg(algorithm: string): string | null {
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
 *
 * upstream: util/JWEUtil.java
 */
export function createSymmetricJWKForAlgAndSecret(
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
		const secretBytes = deriveEncryptionKey(algorithm, secret);
		key = build(secretBytes);
	} else if ("dir" === algorithm) {
		if (encMethod == null) {
			throw new TypeError('Cannot invoke "com.nimbusds.jose.EncryptionMethod.getName()" because "encMethod" is null');
		}
		const secretBytes = deriveEncryptionKey(encMethod, secret);
		key = build(secretBytes);
	}
	return key;
}

/**
 * Java overloads `createDecrypter(JWK)`, `createDecrypter(String, JWK)` and `createDecrypter(Algorithm, JWK)`:
 * pass either just the key (its `alg` is used) or the algorithm name and the key.
 *
 * @return AESDecrypter or DirectDecrypter or RSADecrypter or ECDHDecrypter or X25519Decrypter (as a
 *   {@link JWEDecrypter})
 * @throws JOSEException
 *
 * upstream: util/JWEUtil.java
 */
export function createDecrypter(key: JWK): JWEDecrypter;
export function createDecrypter(algorithm: string, key: JWK | null): JWEDecrypter;
export function createDecrypter(algorithmOrKey: string | JWK, maybeKey?: JWK | null): JWEDecrypter {
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
		checkAesKeyLength(castKey(key, "oct"));
		const decrypter = new JWEDecrypter("AESDecrypter", algorithm, key);
		return decrypter;
	} else if (DIRECT_SUPPORTED_ALGORITHMS.includes(algorithm)) {
		checkDirectKeyLength(castKey(key, "oct"));
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

/** upstream: util/JWEUtil.java */
export function isAsymmetricJWEAlgorithm(algorithmName: string | null | undefined): boolean {
	algorithmName = requireAlgorithmName(algorithmName);
	return JWE_FAMILY_ASYMMETRIC.includes(algorithmName);
}

/** upstream: util/JWEUtil.java */
export function isSymmetricJWEAlgorithm(algorithmName: string | null | undefined): boolean {
	algorithmName = requireAlgorithmName(algorithmName);
	return JWE_FAMILY_SYMMETRIC.includes(algorithmName);
}
