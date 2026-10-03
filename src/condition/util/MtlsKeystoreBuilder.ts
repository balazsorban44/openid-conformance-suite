import { X509Certificate, type KeyObject } from "node:crypto";
import type { Environment } from "../../framework/index.ts";
import { MtlsKeyUtil } from "../../util/MtlsKeyUtil.ts";

/**
 * The TypeScript equivalent of the javax.net.ssl.KeyManager[] returned by the Java builder: the client certificate
 * chain and private key, as PEM, ready to be passed as `cert` / `key` to node:tls / undici.
 */
export interface MtlsKeyManager {
	/** the client certificate followed by the optional CA chain, PEM encoded */
	cert: string;
	/** the unencrypted PKCS#8 private key, PEM encoded */
	key: string;
}

export class MtlsKeystoreBuilder {
	static configureMtls(env: Environment): MtlsKeyManager {
		const clientCert = env.getString("mutual_tls_authentication", "cert") as string;
		const clientKey = env.getString("mutual_tls_authentication", "key") as string;
		const clientCa = env.getString("mutual_tls_authentication", "ca");

		const certBytes = Buffer.from(clientCert, "base64");
		const keyBytes = Buffer.from(clientKey, "base64");

		const cert = MtlsKeystoreBuilder.generateCertificateFromDER(certBytes);

		// use public key from cert to aid in decoding the private key
		// which can be EC or RSA keys in PKCS#1 or PKCS#8 format
		const publicKey = cert.publicKey;
		const alg = MtlsKeystoreBuilder.javaKeyAlgorithm(publicKey.asymmetricKeyType);

		const key: KeyObject = MtlsKeyUtil.generateAlgPrivateKeyFromDER(alg, keyBytes);

		const chain: X509Certificate[] = [cert];
		if (clientCa != null) {
			const caBytes = Buffer.from(clientCa, "base64");
			chain.push(...MtlsKeystoreBuilder.generateCertificateChainFromDER(caBytes));
		}

		// Java builds a JKS keystore with the key + chain and wraps it in a KeyManagerFactory; node:tls takes the
		// PEM chain and key directly.
		return {
			cert: chain.map((c) => c.toString()).join("\n"),
			key: key.export({ type: "pkcs8", format: "pem" }) as string,
		};
	}

	/** The JCA algorithm name (PublicKey.getAlgorithm()) for a node asymmetricKeyType */
	private static javaKeyAlgorithm(type: string | undefined): string {
		switch (type) {
			case "rsa":
				return "RSA";
			case "rsa-pss":
				return "RSASSA-PSS";
			case "ec":
				return "EC";
			case "ed25519":
				return "Ed25519";
			case "ed448":
				return "Ed448";
			default:
				return String(type);
		}
	}

	protected static generateCertificateFromDER(certBytes: Uint8Array): X509Certificate {
		return new X509Certificate(certBytes);
	}

	protected static generateCertificateChainFromDER(chainBytes: Uint8Array): X509Certificate[] {
		const chain: X509Certificate[] = [];
		let offset = 0;
		while (offset < chainBytes.length) {
			// each certificate is a DER SEQUENCE: tag 0x30, then the length
			if (chainBytes[offset] !== 0x30) {
				throw new Error("Could not parse certificate: not a DER SEQUENCE at offset " + offset);
			}
			let length = chainBytes[offset + 1] as number;
			let headerLength = 2;
			if (length >= 0x80) {
				const lengthBytes = length & 0x7f;
				length = 0;
				for (let i = 0; i < lengthBytes; i++) {
					length = length * 256 + (chainBytes[offset + 2 + i] as number);
				}
				headerLength = 2 + lengthBytes;
			}
			const end = offset + headerLength + length;
			chain.push(new X509Certificate(chainBytes.subarray(offset, end)));
			offset = end;
		}

		return chain;
	}
}
