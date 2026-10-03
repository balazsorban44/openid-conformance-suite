import { createPublicKey, X509Certificate, type KeyObject } from "node:crypto";
import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { ECKeyUtil } from "../../util/ECKeyUtil.ts";
import { IllegalArgumentException, javaBase64Decode } from "../../util/jdk/strings.ts";
import { CertificateException, generateCertificates, javaKeyAlgorithm } from "../../util/jdk/x509.ts";
import { InvalidKeySpecException, MtlsKeyUtil } from "../../util/MtlsKeyUtil.ts";

export class ValidateMTLSCertificatesAsX509 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["mutual_tls_authentication"] };

	override evaluate(env: Environment): Environment {
		const certString = env.getString("mutual_tls_authentication", "cert");
		const keyString = env.getString("mutual_tls_authentication", "key");
		const caString = env.getString("mutual_tls_authentication", "ca");

		if (!certString || !keyString) {
			throw this.error("Couldn't find TLS client certificate or key for MTLS");
		}

		// CertificateFactory.getInstance("X.509", BouncyCastleProviderSingleton.getInstance()) cannot fail with
		// node:crypto ("Couldn't get CertificateFactory")

		const certificate = this.generateCertificateFromMTLSCert(certString);

		this.validateMTLSKey(certString, keyString, certificate);

		if (caString) {
			this.validateMTLSCa(env, caString);
		}

		this.logSuccess("Mutual TLS authentication cert validated as X.509");

		return env;
	}

	private generateCertificateFromMTLSCert(certString: string): X509Certificate {
		let decodedCert: Buffer;
		try {
			decodedCert = javaBase64Decode(certString);
		} catch (e) {
			if (e instanceof IllegalArgumentException) {
				throw this.error("base64 decode of cert failed", e, args("cert", certString));
			}
			throw e;
		}

		let certificate: X509Certificate;
		try {
			certificate = new X509Certificate(decodedCert);
		} catch (e) {
			throw this.error("Calling generateCertificate on cert failed", e, args("cert", certString));
		}
		return certificate;
	}

	private validateMTLSKey(certString: string, keyString: string, certificate: X509Certificate): void {
		let decodedKey: Buffer;
		try {
			decodedKey = javaBase64Decode(keyString);
		} catch (e) {
			if (e instanceof IllegalArgumentException) {
				throw this.error("base64 decode of key failed", e, args("key", keyString));
			}
			throw e;
		}

		const publicKey = certificate.publicKey;
		const alg = javaKeyAlgorithm(publicKey);

		if ("RSA" === alg) {
			this.verifyRSAPrivateKey(certString, keyString, decodedKey, certificate);
		} else if ("EC" === alg) {
			this.verifyECPrivateKey(certString, keyString, decodedKey, certificate);
		} else if ("Ed25519" === alg) {
			// alg value is specific to BouncyCastle provider; use EdDSA if using default Java provider
			this.verifyEd25519PrivateKey(certString, keyString, decodedKey, certificate);
		} else {
			throw this.error(
				"The private key format is not supported. You need to provide a private key which is RSA or EC or EdDSA with Ed25519 curve",
			);
		}
	}

	private verifyRSAPrivateKey(
		certString: string,
		keyString: string,
		decodedKey: Buffer,
		certificate: X509Certificate,
	): void {
		let privateKey: KeyObject;
		try {
			privateKey = MtlsKeyUtil.generateAlgPrivateKeyFromDER("RSA", decodedKey);
		} catch (e) {
			if (e instanceof InvalidKeySpecException) {
				throw this.error("Couldn't generate RSA private key", e, args("key", keyString));
			}
			throw e;
		}

		// Check that the private key and the certificate match
		const rsaPublicKey = certificate.publicKey;
		if (privateKey.export({ format: "jwk" }).n !== rsaPublicKey.export({ format: "jwk" }).n) {
			throw this.error("MTLS Private Key and Cert do not match", args("cert", certString, "key", keyString));
		}
	}

	private verifyECPrivateKey(
		certString: string,
		keyString: string,
		decodedKey: Buffer,
		certificate: X509Certificate,
	): void {
		let privateKey: KeyObject;
		try {
			privateKey = MtlsKeyUtil.generateAlgPrivateKeyFromDER("EC", decodedKey);
		} catch (e) {
			if (e instanceof InvalidKeySpecException) {
				throw this.error("Couldn't generate EC private key", e, args("key", keyString));
			}
			throw e;
		}
		// generate public key from private key and compare with certificate's public key
		const ecPublicKey = certificate.publicKey;
		if (privateKey.asymmetricKeyType === "ec") {
			const bcecDerivedPublicKey = ECKeyUtil.deriveECPubKeyFromPrivKey(privateKey);
			if (!bcecDerivedPublicKey.equals(ecPublicKey)) {
				throw this.error("MTLS Private Key and Cert do not match", args("cert", certString, "key", keyString));
			}
		} else {
			throw this.error("Invalid EC private key instance");
		}
	}

	private verifyEd25519PrivateKey(
		certString: string,
		keyString: string,
		decodedKey: Buffer,
		certificate: X509Certificate,
	): void {
		let privateKey: KeyObject;
		try {
			privateKey = MtlsKeyUtil.generateAlgPrivateKeyFromDER("Ed25519", decodedKey);
		} catch (e) {
			if (e instanceof InvalidKeySpecException) {
				throw this.error("Couldn't generate Ed25519 private key", e, args("key", keyString));
			}
			throw e;
		}
		// Check that the private key and the certificate match
		const pubKey = certificate.publicKey;
		if (pubKey.asymmetricKeyType === "ed25519" && privateKey.asymmetricKeyType === "ed25519") {
			const bcEdPublicKey = pubKey;
			if (!createPublicKey(privateKey).equals(bcEdPublicKey)) {
				throw this.error("Ed25519 MTLS Private Key and Cert do not match", args("cert", certString, "key", keyString));
			}
		} else {
			throw this.error("MTLS Private Key or Cert are not valid instances", args("cert", certString, "key", keyString));
		}
	}

	private validateMTLSCa(env: Environment, caString: string): void {
		let decodedCa: Buffer;
		try {
			decodedCa = javaBase64Decode(caString);
			const caCertificateChainList = generateCertificates(decodedCa);

			let isWrongOrder = false;
			for (let i = 0; i < caCertificateChainList.length; i++) {
				const x509Certificate = caCertificateChainList[i];
				if (this.isSelfSigned(x509Certificate) && i < caCertificateChainList.length - 1) {
					caCertificateChainList.splice(i, 1);
					caCertificateChainList.push(x509Certificate);
					isWrongOrder = true;
					break;
				}
			}

			if (isWrongOrder) {
				this.log("Root & issuing in mtls.ca is wrong order. Automatically correct it (Issuing first, then root)");

				const out = Buffer.concat(caCertificateChainList.map((certificate) => certificate.raw));

				const newCaString = out.toString("base64");
				const mtls = env.getObject("mutual_tls_authentication") as JsonObject;
				mtls["ca"] = newCaString;
				env.putObject("mutual_tls_authentication", mtls);
			}
		} catch (e) {
			if (e instanceof IllegalArgumentException) {
				throw this.error("base64 decode of ca failed", e, args("ca", caString));
			}
			if (e instanceof CertificateException) {
				throw this.error("Couldn't validate ca cert", e, args("ca", caString));
			}
			throw e;
		}
	}

	private isSelfSigned(cert: X509Certificate): boolean {
		try {
			// Try to verify certificate signature with its own public key
			const key = cert.publicKey;
			return cert.verify(key);
		} catch {
			return false;
		}
	}
}
