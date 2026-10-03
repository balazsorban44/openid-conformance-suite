/**
 * Nimbus JWE encryption and decryption on top of jose: the `JWEEncrypter` / `JWEDecrypter` implementations
 * (`AESEncrypter`, `DirectEncrypter`, `RSAEncrypter`, `ECDHEncrypter`, `X25519Encrypter` and the decrypters), their
 * `SUPPORTED_ALGORITHMS` and key length checks, and the Java casts between the Nimbus JWK classes.
 *
 * Not lock-tracked: there is no upstream Java file for this module.
 */
import { CompactEncrypt, compactDecrypt, type CompactJWEHeaderParameters } from "jose";
import type { JsonObject } from "../../framework/json.ts";
import { JWE_FAMILY_AES_GCM_KW, JWE_FAMILY_AES_KW, JWE_FAMILY_ECDH_ES, JWE_FAMILY_RSA } from "./algorithms.ts";
import { KeyLengthException } from "./errors.ts";
import { importKey, toPublicJWK, type JWK } from "./jwk.ts";

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
		const keyJwk = this.name === "AESEncrypter" || this.name === "DirectEncrypter" ? this.key : toPublicJWK(this.key);
		const key = await importKey(keyJwk as JWK, alg);
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
			importKey(this.key, header.alg ?? this.algorithm),
		);
		return plaintext;
	}

	getClass(): { getSimpleName(): string } {
		return { getSimpleName: () => this.name };
	}
}
