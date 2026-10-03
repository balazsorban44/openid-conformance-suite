import { createPrivateKey, type KeyObject } from "node:crypto";

/** Port of `java.security.spec.InvalidKeySpecException` as thrown by {@link MtlsKeyUtil}. */
export class InvalidKeySpecException extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "InvalidKeySpecException";
	}
}

const KEY_TYPES_FOR_ALG: Record<string, string[]> = {
	RSA: ["rsa", "rsa-pss"],
	EC: ["ec"],
	Ed25519: ["ed25519"],
};

export class MtlsKeyUtil {
	private constructor() {}

	/**
	 * Replaces `generateAlgPrivateKeyFromDER(String, byte[])` returning a `java.security.PrivateKey`: returns a
	 * node:crypto private KeyObject.
	 *
	 * @throws InvalidKeySpecException when the bytes are not a private key of the given algorithm
	 */
	static generateAlgPrivateKeyFromDER(alg: string, keyBytes: Uint8Array): KeyObject {
		try {
			// try to generate private key using PKCS8, works for both RSA and EC and Ed25519 alg
			// RSA alg will handle both PKCS1 and PKCS8 format here
			// EC alg will throw exception for PKCS1, Ed25519 not possible with PKCS1
			const types: ("pkcs8" | "pkcs1")[] = "RSA" === alg ? ["pkcs8", "pkcs1"] : ["pkcs8"];
			return MtlsKeyUtil.createPrivateKeyOfAlg(alg, keyBytes, types);
		} catch (e) {
			if (e instanceof InvalidKeySpecException && "EC" === alg) {
				// try to generate private key using PKCS1
				return MtlsKeyUtil.createPrivateKeyOfAlg(alg, keyBytes, ["sec1"]);
			}
			throw e;
		}
	}

	private static createPrivateKeyOfAlg(
		alg: string,
		keyBytes: Uint8Array,
		types: ("pkcs8" | "pkcs1" | "sec1")[],
	): KeyObject {
		let lastError: unknown = null;
		for (const type of types) {
			try {
				const key = createPrivateKey({ key: Buffer.from(keyBytes), format: "der", type });
				const allowed = KEY_TYPES_FOR_ALG[alg];
				if (allowed && !allowed.includes(key.asymmetricKeyType as string)) {
					throw new InvalidKeySpecException(
						"key spec not recognized: " + key.asymmetricKeyType + " key is not a " + alg + " key",
					);
				}
				return key;
			} catch (e) {
				lastError = e;
			}
		}
		if (lastError instanceof InvalidKeySpecException) {
			throw lastError;
		}
		throw new InvalidKeySpecException("encoded key spec not recognized: " + (lastError as Error)?.message, {
			cause: lastError,
		});
	}
}
