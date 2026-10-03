import { createHash, X509Certificate } from "node:crypto";
import { CompactSign, errors, type CompactJWSHeaderParameters } from "jose";
import {
	args,
	ConditionError,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type JsonObject,
	type JsonValue,
} from "../../framework/index.ts";
import { JOSEException, KeyLengthException } from "../../util/JWEUtil.ts";
import {
	JWKUtil,
	JWS_FAMILY_EC,
	JWS_FAMILY_ED,
	JWS_FAMILY_HMAC_SHA,
	JWS_FAMILY_RSA,
	ParseException,
	type JWK,
} from "../../util/JWKUtil.ts";
import { JWTUtil } from "../../util/JWTUtil.ts";
import { AbstractGetSigningKey } from "./AbstractGetSigningKey.ts";

/** Nimbus ECDSA.resolveAlgorithm(Curve) */
const EC_CURVE_ALGORITHM: Record<string, string> = {
	"P-256": "ES256",
	secp256k1: "ES256K",
	"P-384": "ES384",
	"P-521": "ES512",
};

/** Nimbus ECDSASigner.SUPPORTED_ALGORITHMS etc. (Ed25519Signer supports EdDSA and Ed25519) */
const ED25519_SIGNER_ALGORITHMS: readonly string[] = ["EdDSA", "Ed25519"];

/**
 * Replaces the Nimbus `JWSSigner` implementations used by the conformance suite (`RSASSASigner`, `ECDSASigner`,
 * `MACSigner`, `Ed25519Signer`) on top of jose. `new SignedJWT(header, claimSet).sign(signer); serialize()` becomes
 * `await signer.sign(header, payload)`.
 *
 * Not in upstream as such: a candidate to move to src/util (e.g. JWSUtil) so other conditions can share it.
 */
export class JWSSigner {
	/** The Nimbus class name (Java `getClass().getSimpleName()`). */
	readonly name: string;
	readonly jwk: JWK;
	private readonly algorithms: readonly string[];

	private constructor(name: string, jwk: JWK, algorithms: readonly string[]) {
		this.name = name;
		this.jwk = jwk;
		this.algorithms = algorithms;
	}

	/** Nimbus `JWSProvider.supportedJWSAlgorithms()` */
	supportedJWSAlgorithms(): readonly string[] {
		return this.algorithms;
	}

	/**
	 * Signs `payload` with the given (protected) JWS header and returns the compact serialization.
	 * Replaces Nimbus `JWSObject.sign(signer)` + `serialize()`.
	 *
	 * @throws JOSEException (or a jose error)
	 */
	async sign(header: JsonObject, payload: string | Uint8Array): Promise<string> {
		const alg = header["alg"] as string;
		// JWSObject.ensureJWSSignerSupport
		if (!this.algorithms.includes(alg)) {
			throw new JOSEException(
				"The " +
					alg +
					" algorithm is not allowed or supported by the JWS signer: Supported algorithms: [" +
					this.algorithms.join(", ") +
					"]",
			);
		}
		const key = await JWKUtil.importKey(this.jwk, alg);
		const bytes = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
		return await new CompactSign(bytes).setProtectedHeader(header as CompactJWSHeaderParameters).sign(key);
	}

	/** Nimbus `new RSASSASigner((RSAKey) jwk)` */
	static rsa(jwk: JWK): JWSSigner {
		if (!JWKUtil.isPrivate(jwk)) {
			throw new JOSEException("The RSA JWK doesn't contain a private part");
		}
		return new JWSSigner("RSASSASigner", jwk, JWS_FAMILY_RSA);
	}

	/** Nimbus `new ECDSASigner((ECKey) jwk)` */
	static ec(jwk: JWK): JWSSigner {
		const crv = jwk["crv"];
		if (crv == null) {
			throw new JOSEException("The EC key curve is not supported, must be P-256, P-384 or P-521");
		}
		const alg = EC_CURVE_ALGORITHM[crv];
		if (alg == null) {
			throw new JOSEException("Unexpected curve: " + crv);
		}
		if (!JWKUtil.isPrivate(jwk)) {
			throw new JOSEException("The EC JWK doesn't contain a private part");
		}
		return new JWSSigner("ECDSASigner", jwk, [alg]);
	}

	/** Nimbus `new MACSigner((OctetSequenceKey) jwk)` */
	static mac(jwk: JWK): JWSSigner {
		const bitLength = Buffer.from(String(jwk["k"] ?? ""), "base64url").length * 8;
		if (bitLength < 256) {
			throw new KeyLengthException("The secret length must be at least 256 bits");
		}
		// MACSigner.getCompatibleAlgorithms
		const algorithms: string[] = [];
		if (bitLength >= 256) {
			algorithms.push("HS256");
		}
		if (bitLength >= 384) {
			algorithms.push("HS384");
		}
		if (bitLength >= 512) {
			algorithms.push("HS512");
		}
		return new JWSSigner("MACSigner", jwk, algorithms);
	}

	/** Nimbus `new Ed25519Signer((OctetKeyPair) jwk)` */
	static ed25519(jwk: JWK): JWSSigner {
		if (jwk["crv"] !== "Ed25519") {
			throw new JOSEException("Ed25519Signer only supports OctetKeyPairs with crv=Ed25519");
		}
		if (!JWKUtil.isPrivate(jwk)) {
			throw new JOSEException("The OctetKeyPair doesn't contain a private part");
		}
		return new JWSSigner("Ed25519Signer", jwk, ED25519_SIGNER_ALGORITHMS);
	}

	/**
	 * Nimbus `DefaultJWSSignerFactory.createJWSSigner(jwk, alg)` (also what `MultiJWSSignerFactory` falls back to).
	 *
	 * @throws JOSEException
	 */
	static create(jwk: JWK, alg: string): JWSSigner {
		if (!JWKUtil.isPrivate(jwk)) {
			throw new JOSEException("Expected private JWK but none available");
		}
		if (jwk["use"] != null && jwk["use"] !== "sig") {
			throw new JOSEException("The JWK use must be sig (signature) or unspecified");
		}
		if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
			if (jwk["kty"] !== "oct") {
				throw expectedClass("OctetSequenceKey");
			}
			return JWSSigner.mac(jwk);
		} else if (JWS_FAMILY_RSA.includes(alg)) {
			if (jwk["kty"] !== "RSA") {
				throw expectedClass("RSAKey");
			}
			return JWSSigner.rsa(jwk);
		} else if (JWS_FAMILY_EC.includes(alg)) {
			if (jwk["kty"] !== "EC") {
				throw expectedClass("ECKey");
			}
			return JWSSigner.ec(jwk);
		} else if (JWS_FAMILY_ED.includes(alg)) {
			if (jwk["kty"] !== "OKP") {
				throw expectedClass("OctetKeyPair");
			}
			return JWSSigner.ed25519(jwk);
		}
		throw new JOSEException("Unsupported JWS algorithm: " + alg);
	}
}

/**
 * Replaces Nimbus `JWTClaimsSet.parse(claims.toString())` followed by `toJSONObject(includeNullValues)`:
 * validates the registered claims as Nimbus does and returns them as Nimbus serializes them (without null valued
 * claims unless `includeNullValues`, as `JWTClaimsSet.toPayload()` does).
 *
 * Not in upstream as such: a candidate to move to src/util/JWTUtil.
 *
 * @throws ParseException
 */
export function parseClaimsSet(claims: JsonObject, includeNullValues = false): JsonObject {
	const parsed = JWTUtil.jwtClaimsSetAsJsonObject({
		type: "plain",
		serialized: "",
		parts: [],
		header: { alg: "none" },
		payload: JSON.stringify(claims),
		signature: null,
	});
	if (includeNullValues) {
		return parsed;
	}
	const out: JsonObject = {};
	for (const [k, v] of Object.entries(parsed)) {
		if (v !== null) {
			out[k] = v;
		}
	}
	return out;
}

/** Nimbus `JWKException.expectedClass(cls)` */
function expectedClass(cls: string): JOSEException {
	return new JOSEException("Invalid JWK: Must be an instance of class com.nimbusds.jose.jwk." + cls);
}

/** True for the errors Nimbus would report as a JOSEException (our JOSEException port and jose's own errors). */
export function isJOSEException(e: unknown): e is Error {
	return e instanceof JOSEException || e instanceof errors.JOSEError;
}

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
