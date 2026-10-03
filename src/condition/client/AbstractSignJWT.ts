import { createHash, X509Certificate } from "node:crypto";
import {
	args,
	ConditionError,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type JsonObject,
	type JsonValue,
} from "../../framework/index.ts";
import { JWKUtil, JWS_FAMILY_HMAC_SHA, ParseException, type JWK } from "../../util/JWKUtil.ts";
import { isJOSEException } from "../../util/nimbus/errors.ts";
import { JWSSigner } from "../../util/nimbus/jws.ts";
import { parseClaimsSet } from "../../util/nimbus/jwt.ts";
import { AbstractGetSigningKey } from "./AbstractGetSigningKey.ts";

export abstract class AbstractSignJWT extends AbstractGetSigningKey {
	static readonly ALG_NONE_HEADER: string = Buffer.from('{"alg":"none"}').toString("base64url");

	/** Nimbus `JOSEObjectType.JWT` */
	protected getMediaType(): string {
		return "JWT";
	}

	/**
	 * Expects only one non-encryption JWK in jwks
	 *
	 * Replaces the Java overloads signJWT(env, claims, jwks), signJWT(env, claims, jwks, includeTyp) and
	 * signJWT(env, claims, jwks, includeTyp, includeX5tS256, includeX5c, errorIfX5cMissing).
	 */
	protected async signJWT(
		env: Environment,
		claims: JsonObject | null,
		jwks: JsonObject | null,
		includeTyp = false,
		includeX5tS256 = false,
		includeX5c = false,
		errorIfX5cMissing = false,
	): Promise<Environment> {
		if (claims == null) {
			throw this.error("Couldn't find claims");
		}

		if (jwks == null) {
			throw this.error("Couldn't find jwks");
		}

		try {
			const claimSet = parseClaimsSet(claims, true);
			const signingJwk = this.getSigningKey("signing", jwks);
			const algorithm = signingJwk["alg"];
			if (algorithm == null) {
				throw this.error(
					"No 'alg' field specified in key; please add 'alg' field in the configuration",
					args("jwk", signingJwk),
				);
			}
			const alg = String(algorithm);

			const signer = JWSSigner.create(signingJwk, alg);

			const header: JsonObject = { alg: alg };
			if (includeTyp) {
				header["typ"] = this.getMediaType();
			}
			if (includeX5tS256) {
				const x5tFromJwk = (signingJwk["x5t#S256"] as string | undefined) ?? null;
				const x5c = signingJwk["x5c"];
				const certs = isJsonArray(x5c) ? x5c.map((c) => new X509Certificate(Buffer.from(String(c), "base64"))) : null;
				const hasX5c = certs != null && certs.length > 0;

				if (x5tFromJwk == null && !hasX5c) {
					throw this.error(
						"A x5t#S256 header parameter is required but the signing key in the configuration has neither an x5t#S256 nor an x5c entry",
						args("clientjwks", jwks),
					);
				}

				let x5tS256: string;
				if (hasX5c) {
					// X509CertUtils.computeSHA256Thumbprint
					const computed = createHash("sha256").update(certs[0].raw).digest("base64url");
					if (x5tFromJwk != null && x5tFromJwk !== computed) {
						throw this.error(
							"The x5t#S256 value in the JWK does not match the SHA-256 thumbprint computed from the x5c certificate",
							args("x5t#S256_from_jwk", x5tFromJwk, "x5t#S256_computed_from_x5c", computed),
						);
					}
					x5tS256 = computed;
				} else {
					x5tS256 = x5tFromJwk as string;
				}
				header["x5t#S256"] = x5tS256;
			}
			if (includeX5c) {
				if (signingJwk["x5c"] == null) {
					if (errorIfX5cMissing) {
						throw this.error(
							"A x5c entry is required in the client's signing key but isn't present in the configuration",
							args("clientjwks", jwks),
						);
					}
				} else {
					header["x5c"] = signingJwk["x5c"];
				}
			}
			if (signingJwk["kid"] != null) {
				header["kid"] = signingJwk["kid"];
			}

			const jws = await this.performSigning(header, claims, signer);

			const publicJwk = JWKUtil.toPublicJWK(signingJwk);
			const publicKeySetString = publicJwk != null ? JSON.stringify(publicJwk) : null;
			const verifiableObj: JsonObject = {};
			verifiableObj["verifiable_jws"] = jws;
			verifiableObj["public_jwk"] = publicKeySetString;

			this.logSuccessByJWTType(env, claimSet, signingJwk, header, jws, verifiableObj);

			return env;
		} catch (e) {
			if (e instanceof ConditionError) {
				throw e;
			}
			if (e instanceof ParseException) {
				throw this.error(e);
			}
			if (isJOSEException(e)) {
				throw this.error(
					"Unable to sign client assertion; check provided key has correct 'kty' for it's 'alg': " +
						String(e.cause ?? null),
					e,
				);
			}
			throw e;
		}
	}

	/** @throws JOSEException, ParseException */
	protected async performSigning(header: JsonObject, claims: JsonObject, signer: JWSSigner): Promise<string> {
		const claimSet = parseClaimsSet(claims);

		return await signer.sign(header, JSON.stringify(claimSet));
	}

	/** @throws JOSEException, ParseException */
	protected async performSigningEnsureAudIsArray(
		header: JsonObject,
		claims: JsonObject,
		signer: JWSSigner,
	): Promise<string> {
		const payloadJson = parseClaimsSet(claims);

		/*
		 * The default behaviour of JWTClaimsSet.toJSONObject() is to convert a single element 'aud' claim array to a string.
		 *
		 * Here we ensure it remains an array.
		 */
		const audClaim = claims["aud"];
		if (audClaim != null && isJsonArray(audClaim)) {
			if (typeof payloadJson["aud"] === "string") {
				const audList: JsonValue[] = [payloadJson["aud"]];
				payloadJson["aud"] = audList;
			}
		}

		return await signer.sign(header, JSON.stringify(payloadJson));
	}

	/**
	 * `claimSet` is the claims as Nimbus' JWTClaimsSet renders them, `jwk` the JSON JWK and `header` the JWS header
	 * JSON (replacing the Nimbus JWTClaimsSet, JWK and JWSHeader objects); they are null when Java passes null.
	 */
	protected abstract logSuccessByJWTType(
		env: Environment,
		claimSet: JsonObject | null,
		jwk: JWK | null,
		header: JsonObject | null,
		jws: string,
		verifiableObj: JsonObject | null,
	): void;

	protected signWithAlgNone(input: string): string {
		const jwt = AbstractSignJWT.ALG_NONE_HEADER + "." + Buffer.from(input).toString("base64url") + ".";
		return jwt;
	}

	/**
	 * Creates an OctetSequenceKey is using a symmetric alg and the client secret
	 * or
	 * Selects a key from the jwks
	 * @param jwks
	 * @param signingAlg
	 * @param client
	 * @return
	 */
	selectOrCreateKey(jwks: JsonObject | null, signingAlg: string, client: JsonObject | null): JWK {
		const jwsAlgorithm = signingAlg;
		let selectedKey: JWK | null = null;
		if (JWS_FAMILY_HMAC_SHA.includes(jwsAlgorithm)) {
			//if using MAC based alg, create a jwk from client secret
			const clientSecret = OIDFJSON.getString((client as JsonObject)["client_secret"]);
			selectedKey = JWKUtil.parseJWK({
				kty: "oct",
				use: "sig",
				alg: jwsAlgorithm,
				k: Buffer.from(clientSecret).toString("base64url"),
			});
		} else {
			try {
				// UPSTREAM: Java calls jwks.toString() which throws a NullPointerException when jwks is null
				const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(jwks));
				if (jwkSet != null) {
					const keys = jwkSet.keys;
					selectedKey = JWKUtil.selectAsymmetricJWSKey(jwsAlgorithm, keys);
				}
			} catch (e) {
				if (e instanceof ParseException) {
					throw this.error(
						"Could not parse jwks. Failed to find a signing key.",
						e,
						args("jwks", jwks, "alg", signingAlg),
					);
				}
				throw e;
			}
			//throw an error if a key that will satisfy the alg cannot be found
			if (selectedKey == null) {
				throw this.error(
					"Jwks does not contain a suitable signing key for the selected algorithm",
					args("signing_algorithm", signingAlg),
				);
			}
		}
		return selectedKey;
	}

	protected async signJWTUsingKey(
		env: Environment,
		claims: JsonObject | null,
		jwk: JWK | null,
		alg: string,
	): Promise<Environment> {
		if (claims == null) {
			throw this.error("Couldn't find claims");
		}

		if (jwk == null) {
			throw this.error("A JWK is required for signing");
		}

		try {
			const claimSet = parseClaimsSet(claims, true);
			let signer: JWSSigner | null = null;

			if ("RSA" === jwk["kty"]) {
				signer = JWSSigner.rsa(jwk);
			} else if ("EC" === jwk["kty"]) {
				signer = JWSSigner.ec(jwk);
			} else if ("oct" === jwk["kty"]) {
				signer = JWSSigner.mac(jwk);
			} else if ("OKP" === jwk["kty"]) {
				signer = JWSSigner.ed25519(jwk);
			}

			if (signer == null) {
				throw this.error(
					"Couldn't create signer from key; kty must be one of 'oct', 'rsa', 'ec'",
					args("jwk", JSON.stringify(jwk)),
				);
			}

			const header: JsonObject = { alg: alg };
			if (jwk["kid"] != null) {
				header["kid"] = jwk["kid"];
			}

			const jws = await this.performSigning(header, claims, signer);

			const publicJwk = JWKUtil.toPublicJWK(jwk);
			const publicKeySetString = publicJwk != null ? JSON.stringify(publicJwk) : null;
			const verifiableObj: JsonObject = {};
			verifiableObj["verifiable_jws"] = jws;
			verifiableObj["public_jwk"] = publicKeySetString;

			this.logSuccessByJWTType(env, claimSet, jwk, header, jws, verifiableObj);

			return env;
		} catch (e) {
			if (e instanceof ConditionError) {
				throw e;
			}
			if (e instanceof ParseException) {
				throw this.error(e);
			}
			if (isJOSEException(e)) {
				let message = e.message;
				if (e.cause instanceof Error) {
					message = message + " (" + e.cause.message + ")";
				}
				throw this.error("Unable to sign: " + message, e);
			}
			throw e;
		}
	}
}
