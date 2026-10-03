import { errors } from "jose";
import { args, type JsonObject } from "../../framework/index.ts";
import { JWEUtil, JOSEException, KeyLengthException, type JWEEncrypter } from "../../util/JWEUtil.ts";
import { JWE_FAMILY_ASYMMETRIC, ParseException, type JWK, type JWKSet } from "../../util/JWKUtil.ts";
import { AbstractLenientJwksCondition } from "../AbstractLenientJwksCondition.ts";

/** Nimbus JOSEException equivalents: the util's JOSEException, jose's errors, and jose's key validation TypeErrors */
function isJOSEException(e: unknown): boolean {
	return e instanceof JOSEException || e instanceof errors.JOSEError || e instanceof TypeError;
}

/**
 * Can be used to encrypt id tokens, userinfo responses, request objects
 */
export abstract class AbstractJWEEncryptString extends AbstractLenientJwksCondition {
	/**
	 *
	 * @param destination the entity the object is for (usually client or server)
	 * @param stringToBeEncrypted e.g the id_token as string
	 * @param clientSecret null if encryptor has no secret, e.g using private_key_jwt
	 * @param jwksJsonObject null if destination does not have a jwks
	 * @param alg as per JWE RFC
	 * @param enc as per JWE RFC
	 * @param algMetadataName used for logging only
	 * @param encMetadataName used for logging only
	 * @param cty content type for the JWE header (Java overload without cty/apu/apv uses "JWT")
	 * @param apu base64url encoded agreement PartyUInfo, or null
	 * @param apv base64url encoded agreement PartyVInfo, or null
	 * @return string containing resulting JWE
	 */
	async encrypt(
		destination: string,
		stringToBeEncrypted: string,
		clientSecret: string | null,
		jwksJsonObject: JsonObject | null,
		alg: string | null,
		enc: string | null,
		algMetadataName: string,
		encMetadataName: string,
		cty: string | null = "JWT",
		apu: string | null = null,
		apv: string | null = null,
	): Promise<string> {
		if (alg == null) {
			throw this.error(
				algMetadataName +
					" is not defined for the " +
					destination +
					". This is a bug in the test module. skipIfElementMissing should be used",
			);
		}

		if (enc != null && alg == null) {
			throw this.error(
				encMetadataName +
					" is set but " +
					algMetadataName +
					" is not set for the " +
					destination +
					"." +
					" When " +
					encMetadataName +
					" is set, " +
					algMetadataName +
					" MUST also be provided.",
			);
		}

		//https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
		//id_token_encrypted_response_enc
		//  OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client.
		//  If id_token_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
		//Also for JARM:
		// ...If authorization_encrypted_response_alg is specified, the default for this value is A128CBC-HS256...
		let encryptionMethod = "A128CBC-HS256";
		if (enc != null) {
			encryptionMethod = enc;
		}
		const algorithm = alg;

		let recipientJWK: JWK | null = null;
		if (JWE_FAMILY_ASYMMETRIC.includes(algorithm)) {
			//asymmetric key
			if (jwksJsonObject == null) {
				throw this.error(destination + " jwks is required for " + algorithm + " algorithm");
			}
			let jwks: JWKSet;
			try {
				// parse leniently: ignore keys whose curve/type the JOSE library cannot handle (e.g.
				// Brainpool, or future post-quantum keys), so a usable key elsewhere in the set can
				// still be selected; skipped keys are logged
				jwks = this.parseJwksLenientlyLoggingSkips(JSON.stringify(jwksJsonObject), destination);
			} catch (e) {
				if (e instanceof ParseException) {
					throw this.error("Failed to parse " + destination + " jwks", e, args("jwks", jwksJsonObject));
				}
				throw e;
			}
			recipientJWK = JWEUtil.selectAsymmetricKeyForEncryption(jwks, algorithm);
			if (recipientJWK == null) {
				throw this.error(
					"A key suitable for encrypting the JWT was not found in the " + destination + " JWKS.",
					args("algorithm", algorithm, "jwks", jwksJsonObject),
				);
			}
		} else {
			//symmetric key
			try {
				// UPSTREAM: clientSecret may be null here (e.g. no client_secret registered), which crashes like
				// the Java NullPointerException
				recipientJWK = JWEUtil.createSymmetricJWKForAlgAndSecret(
					clientSecret as string,
					algorithm,
					encryptionMethod,
					null,
				);
			} catch (e) {
				if (e instanceof KeyLengthException) {
					throw this.error("Failed to create symmetric encryption key", e, args("algorithm", algorithm));
				}
				throw e;
			}
			if (recipientJWK == null) {
				throw this.error("Failed to derive symmetric key", args("algorithm", algorithm));
			}
		}

		// Encrypt with the recipient's public key
		let jweEncrypter: JWEEncrypter | null = null;
		try {
			jweEncrypter = JWEUtil.createEncrypter(recipientJWK);
		} catch (e) {
			if (e instanceof JOSEException) {
				throw this.error("Failed to create jwk encrypter", e);
			}
			throw e;
		}

		const jweHeader: JsonObject = { alg: algorithm, enc: encryptionMethod };
		if (cty != null) {
			jweHeader["cty"] = cty;
		}
		const keyID = recipientJWK["kid"];
		if (typeof keyID === "string" && keyID !== "") {
			jweHeader["kid"] = keyID;
		}
		if (apu != null) {
			jweHeader["apu"] = apu;
		}
		if (apv != null) {
			jweHeader["apv"] = apv;
		}
		let jweString: string;
		try {
			// Serialise to JWE compact form
			jweString = await (jweEncrypter as JWEEncrypter).encrypt(jweHeader, stringToBeEncrypted);
		} catch (e) {
			if (isJOSEException(e)) {
				throw this.error(
					"Encryption failed",
					e,
					args("encrypter", (jweEncrypter as JWEEncrypter).getClass().getSimpleName()),
				);
			}
			throw e;
		}

		return jweString;
	}
}
