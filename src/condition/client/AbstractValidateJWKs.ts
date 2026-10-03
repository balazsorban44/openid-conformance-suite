import { X509Certificate, type KeyObject } from "node:crypto";
import { compactVerify, errors } from "jose";
import {
	AbstractCondition,
	args,
	ConditionError,
	ex,
	isJsonArray,
	isJsonObject,
	OIDFJSON,
	type JsonArray,
	type JsonObject,
	type JsonValue,
} from "../../framework/index.ts";
import {
	JWKUtil,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	ParseException,
	type JWK,
	type JWKSet,
} from "../../util/JWKUtil.ts";
import { isJOSEException, JWSSigner, parseClaimsSet } from "./AbstractSignJWT.ts";

/** A signed JWT: its header and compact serialization (replaces Nimbus SignedJWT). */
interface SignedJWT {
	header: JsonObject;
	serialized: string;
}

/** Nimbus `KeyType.forAlgorithm` for JWS algorithms */
function keyTypeForJWSAlgorithm(alg: string): string | null {
	if (JWS_FAMILY_RSA.includes(alg)) {
		return "RSA";
	} else if (JWS_FAMILY_EC.includes(alg)) {
		return "EC";
	} else if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		return "oct";
	} else if (JWS_FAMILY_ED.includes(alg)) {
		return "OKP";
	}
	return null;
}

/** Nimbus `Curve.forJWSAlgorithm` for the ED family */
function curvesForEdAlgorithm(alg: string): string[] {
	if (alg === "Ed25519") {
		return ["Ed25519"];
	}
	return ["Ed25519", "Ed448"];
}

/**
 * Nimbus `JWKMatcher.forJWSHeader(header)` applied to the keys of `jwkSet` (as used by
 * AlternateJWSVerificationKeySelector.selectJWSJwks). Returns an empty list for an unsupported algorithm.
 */
function selectJWSJwks(header: JsonObject, jwkSet: JWKSet): JWK[] {
	const alg = header["alg"] as string;
	const kid = (header["kid"] as string | undefined) ?? null;
	const kty = keyTypeForJWSAlgorithm(alg);
	if (kty == null) {
		return [];
	}
	const matches: JWK[] = [];
	for (const jwk of jwkSet.keys) {
		if (jwk["kty"] !== kty) {
			continue;
		}
		if (kid != null && jwk["kid"] !== kid) {
			continue;
		}
		if (jwk["alg"] != null && jwk["alg"] !== alg) {
			continue;
		}
		if (kty === "oct") {
			// privateOnly(true) - symmetric keys are always private; no use restriction for HMAC
		} else if (jwk["use"] != null && jwk["use"] !== "sig") {
			continue;
		}
		if (kty === "OKP" && !curvesForEdAlgorithm(alg).includes(jwk["crv"] as string)) {
			continue;
		}
		matches.push(jwk);
	}
	// Get non-EdDSA keys from original function
	const sanitizedJWKs: JWK[] = [];
	for (const jwk of matches) {
		if (jwk["kty"] !== "oct") {
			sanitizedJWKs.push(JWKUtil.toPublicJWK(jwk) as JWK);
			if (JWKUtil.isPrivate(jwk)) {
				sanitizedJWKs.push(jwk);
			}
		} else {
			sanitizedJWKs.push(jwk);
		}
	}
	return sanitizedJWKs;
}

/** RFC 8410 key types (node:crypto `asymmetricKeyType`) for the OKP curves; replaces the OID comparison. */
const OKP_CURVE_KEY_TYPES: Record<string, string> = {
	Ed25519: "ed25519",
	Ed448: "ed448",
	X25519: "x25519",
	X448: "x448",
};

export abstract class AbstractValidateJWKs extends AbstractCondition {
	// RFC 8410 object identifiers for the OKP curves (Nimbus's Curve leaves the OID null for these).
	// (TS: compared as node:crypto asymmetricKeyType values, see OKP_CURVE_KEY_TYPES)

	protected async checkJWKs(jwks: JsonValue | undefined, checkPrivatePart: boolean): Promise<void> {
		if (jwks == null) {
			throw this.error("Couldn't find JWKS in configuration");
		}
		if (!isJsonObject(jwks)) {
			throw this.error(
				"Invalid JWKS (Json Web Key Set) in configuration - it must be a JSON object that contains a 'keys' array.",
				args("jwks", jwks),
			);
		}
		const jwksObject = jwks;
		if (!JWKUtil.hasKeysArray(jwksObject)) {
			throw this.error("Keys array not found in JWKS", args("jwks", jwks));
		}

		const structuralIssues = JWKUtil.findStructurallyInvalidKeys(jwksObject);
		if (structuralIssues.length > 0) {
			const first = structuralIssues[0];
			throw this.error(
				"Invalid JWK in JWKS: the key at index " + first.index + " " + first.detail,
				args("issues", JWKUtil.issuesToJson(structuralIssues)),
			);
		}

		for (const keyJsonElement of jwksObject["keys"] as JsonArray) {
			const keyObject = keyJsonElement as JsonObject;
			// Nimbus performs additional checks the structural scan above does not (e.g. x5c bare-key match).
			this.parseJWKWithNimbus(keyObject);
			if (checkPrivatePart) {
				await this.verifyPrivatePart(jwks, keyObject);
			}
		}
	}

	/**
	 * Nimbusds performs various checks (including the ones manually implemented in this class)
	 * @param keyObject
	 */
	protected parseJWKWithNimbus(keyObject: JsonObject): void {
		let jwk: JWK;
		try {
			//https://openid.net/specs/openid-connect-registration-1_0.html#rfc.section.2
			//jwks
			//    The JWK x5c parameter MAY be used to provide X.509 representations of keys provided.
			//    When used, the bare key values MUST still be present and MUST match those in the certificate
			//Nimbusds enforces this (and other checks like missing properties) for RSA and EC keys while
			//parsing, but NOT for OKP keys: OctetKeyPair.matches() always returns false and its constructor
			//never calls it (see https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/620), so for OKP
			//keys we perform the bare-key-to-certificate check ourselves below.
			jwk = JWKUtil.parseJWK(JSON.stringify(keyObject));
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Invalid JWK", e, args("key", keyObject));
			}
			throw e;
		}
		if (jwk["kty"] === "OKP") {
			this.ensureOkpKeyMatchesCertificate(jwk, keyObject);
		}
	}

	/**
	 * Enforce RFC 7517 section 4.7: when an OKP JWK carries an x5c certificate chain, the bare public
	 * key ("x") MUST match the public key in the leaf certificate. Nimbus performs the equivalent check
	 * for RSA and EC keys during parsing, but `OctetKeyPair#matches(X509Certificate)` is a stub
	 * that always returns false, so the check is skipped for OKP keys (e.g. Ed25519). See
	 * <a href="https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/620">nimbus-jose-jwt issue 620</a>.
	 */
	private ensureOkpKeyMatchesCertificate(okp: JWK, keyObject: JsonObject): void {
		const x5c = okp["x5c"];
		if (!isJsonArray(x5c) || x5c.length === 0) {
			return;
		}
		const certKey: KeyObject = new X509Certificate(Buffer.from(String(x5c[0]), "base64")).publicKey;
		// An OKP public key is (crv, x), so both the curve (the certificate's algorithm OID) and the bare
		// key octets must match; comparing only "x" would let a same-length key on another curve through.
		const expectedKeyType = OKP_CURVE_KEY_TYPES[okp["crv"] as string];
		const curveMismatch = expectedKeyType != null && expectedKeyType !== certKey.asymmetricKeyType;
		let keyMismatch = true;
		if (Object.values(OKP_CURVE_KEY_TYPES).includes(certKey.asymmetricKeyType as string)) {
			const certX = certKey.export({ format: "jwk" }).x as string;
			keyMismatch = !Buffer.from(certX, "base64url").equals(Buffer.from(String(okp["x"]), "base64url"));
		}
		if (curveMismatch || keyMismatch) {
			throw this.error(
				"The JWK supplied in the test configuration has an x5c certificate whose public key " +
					"does not match the bare key (the 'crv' and 'x' values)",
				args("key", keyObject),
			);
		}
	}

	private async verifyPrivatePart(jwks: JsonValue, keyObject: JsonObject): Promise<void> {
		if (!("d" in keyObject)) {
			throw this.error(
				"The JWK supplied in the configuration seems to be a public key (the 'd' key is missing). You must supply a private key in the test configuration.",
				args("jwk", keyObject),
			);
		}

		this.verifyKeysIsBase64UrlEncoded(keyObject, "d");

		await this.checkValidKey(jwks);
	}

	private async checkValidKey(jwks: JsonValue): Promise<void> {
		const claimObject: JsonObject = {};
		claimObject["test"] = "does private/public exponent match?";

		try {
			const claimSet = parseClaimsSet(claimObject);
			const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(jwks));
			let count = 0;
			let signingJwk: JWK | null = null;
			for (const jwk of jwkSet.keys) {
				const use = jwk["use"];
				if (use != null && use !== "sig") {
					// skip any encryption keys
					continue;
				}
				if (signingJwk == null) {
					signingJwk = jwk;
				}
				count++;
			}
			if (count > 1) {
				throw this.error("The JWKS contains more than one signing key.", args("jwks", jwks));
			}
			if (count > 0) {
				// sign jwt using private key
				const jwt = await this.signJWT(signingJwk as JWK, claimSet);

				// Verify JWT after signed to check valid JWKs
				await this.verifyJWTAfterSigned(jwkSet, jwt);
			}
		} catch (e) {
			if (e instanceof ConditionError) {
				throw e;
			}
			if (isJOSEException(e) || e instanceof ParseException) {
				throw this.error("Error validating JWKS", ex(e, args("jwks", jwks)));
			}
			throw e;
		}
	}

	/** @throws JOSEException */
	private async signJWT(jwk: JWK, claimSet: JsonObject): Promise<SignedJWT> {
		let signer: JWSSigner | null = null;
		if (jwk["kty"] === "RSA") {
			signer = JWSSigner.rsa(jwk);
		} else if (jwk["kty"] === "EC") {
			signer = JWSSigner.ec(jwk);
		} else if (jwk["kty"] === "OKP") {
			if ("Ed25519" === jwk["crv"]) {
				signer = JWSSigner.ed25519(jwk);
			} else {
				throw this.error("Unsupported curve for EdDSA alg", args("jwk", JSON.stringify(jwk)));
			}
		}

		if (signer == null) {
			throw this.error("Couldn't create signer from key", args("jwk", JSON.stringify(jwk)));
		}

		const alg = jwk["alg"];
		if (alg == null) {
			throw this.error(
				"keys supplied in the test configuration must contain an 'alg' entry that indicates which algorithm will be used for the test (e.g. 'PS256')",
				args("jwk", JSON.stringify(jwk)),
			);
		}

		const header: JsonObject = { alg: String(alg), typ: "JWT" };
		if (jwk["kid"] != null) {
			header["kid"] = jwk["kid"];
		}

		const serialized = await signer.sign(header, JSON.stringify(claimSet));
		return { header, serialized };
	}

	/** @throws JOSEException */
	private async verifyJWTAfterSigned(jwkSet: JWKSet, jwt: SignedJWT): Promise<void> {
		const alg = jwt.header["alg"] as string;

		const jwkKeys = selectJWSJwks(jwt.header, jwkSet);
		for (const jwkKey of jwkKeys) {
			let verifier: Awaited<ReturnType<typeof JWKUtil.importKey>> | null = null;
			try {
				if (jwkKey["kty"] === "OKP") {
					const publicKey = JWKUtil.parseJWK(JSON.stringify(JWKUtil.toPublicJWK(jwkKey)));
					if ("Ed25519" === publicKey["crv"]) {
						verifier = await JWKUtil.importKey(publicKey, alg);
					}
				} else if (jwkKey["kty"] === "oct") {
					verifier = await JWKUtil.importKey(jwkKey, alg);
				} else {
					// toKeyPair().getPublic()
					verifier = await JWKUtil.importKey(JWKUtil.toPublicJWK(jwkKey) as JWK, alg);
				}
			} catch (e) {
				if (!(isJOSEException(e) || e instanceof ParseException || e instanceof TypeError)) {
					throw e;
				}
				this.log("Unable to verifyJWTAfterSigned", args("exception", e));
			}
			if (verifier != null) {
				let verified: boolean;
				try {
					await compactVerify(jwt.serialized, verifier, { algorithms: [alg] });
					verified = true;
				} catch (e) {
					if (!(e instanceof errors.JWSSignatureVerificationFailed)) {
						throw e;
					}
					verified = false;
				}
				if (!verified) {
					throw this.error(
						"Invalid JWKs supplied in configuration. Private and public exponent don't match (test JWS could not be verified)",
						args("jws", jwt.serialized, "jwks", JWKUtil.getPrivateJwksAsJsonObject(jwkSet)),
					);
				}
			}
		}
	}

	private verifyKeysIsBase64UrlEncoded(keyObject: JsonObject, ...keys: string[]): void {
		for (const key of keys) {
			const value = OIDFJSON.getString(keyObject[key]);
			if (!JWKUtil.isBase64Url(value)) {
				throw this.error("Value of key " + key + " is not valid unpadded base64url", args("jwk", keyObject));
			}
		}
	}
}
