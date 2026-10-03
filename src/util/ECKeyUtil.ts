import { createPublicKey, type KeyObject } from "node:crypto";

export class ECKeyUtil {
	private constructor() {}

	/**
	 * Replaces `deriveECPubKeyFromPrivKey(BCECPrivateKey)`: takes and returns node:crypto KeyObjects. Compare the
	 * result with a certificate's public key using `KeyObject.equals()` (Java: `BCECPublicKey.equals`).
	 */
	static deriveECPubKeyFromPrivKey(bcecPrivateKey: KeyObject): KeyObject {
		// Java multiplies the base point G by the private scalar 'd' to get the public point Q;
		// node:crypto derives the public key from the private key the same way
		return createPublicKey(bcecPrivateKey);
	}
}
