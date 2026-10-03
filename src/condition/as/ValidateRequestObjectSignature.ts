import { createHash, X509Certificate } from "node:crypto";
import { compactVerify, errors } from "jose";
import {
	args,
	has,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";
import { JOSEException } from "../../util/JWEUtil.ts";
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
import { JWTUtil, type JWT } from "../../util/JWTUtil.ts";
import { AbstractLenientJwksCondition } from "../AbstractLenientJwksCondition.ts";

/**
 * Nimbus SignedJWT.parse(s): like JWTParser.parse, but only accepts a JWS.
 * @throws ParseException
 */
function parseSignedJWT(s: string): JWT {
	const jwt = JWTUtil.parseJWT(s);
	if (jwt.type !== "signed") {
		if (jwt.parts.length !== 3) {
			throw new ParseException("Unexpected number of Base64URL parts, must be three");
		}
		throw new ParseException("Invalid JWS header: Not a JWS header");
	}
	return jwt;
}

/** Nimbus KeyType.forAlgorithm for JWS algorithms */
function keyTypeForJwsAlgorithm(alg: string): string | null {
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

/** Nimbus Curve.forJWSAlgorithm */
function curvesForJwsAlgorithm(alg: string): string[] | null {
	switch (alg) {
		case "ES256":
			return ["P-256"];
		case "ES256K":
			return ["secp256k1"];
		case "ES384":
			return ["P-384"];
		case "ES512":
			return ["P-521"];
		case "EdDSA":
			return ["Ed25519", "Ed448"];
		default:
			return null;
	}
}

/** Nimbus ECDSA.resolveAlgorithm(Curve): the only JWS algorithm an ECDSAVerifier supports for the key's curve */
const ECDSA_ALGORITHM_FOR_CURVE: Record<string, string> = {
	"P-256": "ES256",
	secp256k1: "ES256K",
	"P-384": "ES384",
	"P-521": "ES512",
};

/** Nimbus MACProvider.getMinRequiredSecretLength */
const MAC_MIN_SECRET_BITS: Record<string, number> = { HS256: 256, HS384: 384, HS512: 512 };

/** Critical header params Nimbus verifiers process themselves (CriticalHeaderParamsDeferral) */
const PROCESSED_CRITICAL_HEADER_PARAMS = ["b64"];

/** Nimbus JWKMatcher x5t#S256 match: on the key's x5t#S256, or the thumbprint of the first x5c certificate */
function matchesX5tS256(jwk: JWK, x5tS256: string): boolean {
	let matchingCertFound = false;
	const x5c = jwk["x5c"];
	if (Array.isArray(x5c) && x5c.length > 0) {
		try {
			const cert = new X509Certificate(Buffer.from(String(x5c[0]), "base64"));
			matchingCertFound = createHash("sha256").update(cert.raw).digest("base64url") === x5tS256;
		} catch {
			// Ignore
		}
	}
	const matchingX5T256Found = jwk["x5t#S256"] === x5tS256;
	return matchingCertFound || matchingX5T256Found;
}

/** JWKMatcher keyUses(KeyUse.SIGNATURE, null) */
function useMatches(jwk: JWK): boolean {
	return jwk["use"] == null || jwk["use"] === "sig";
}

/**
 * Port of extensions/AlternateJWSVerificationKeySelector.selectJWSJwks (with Nimbus JWKMatcher.forJWSHeader),
 * selecting from an ImmutableJWKSet. Returns the public JWK of every matching asymmetric key (followed by the
 * private JWK itself when it is private) and every matching symmetric key.
 */
function selectJWSJwks(header: JsonObject, jwkSet: JWKSet): JWK[] {
	const alg = header["alg"] as string;
	const kid = typeof header["kid"] === "string" ? header["kid"] : null;
	const x5tS256 = typeof header["x5t#S256"] === "string" ? header["x5t#S256"] : null;
	let matches: (jwk: JWK) => boolean;
	const kty = keyTypeForJwsAlgorithm(alg);
	const algMatches = (jwk: JWK) => jwk["alg"] == null || jwk["alg"] === alg;
	const kidMatches = (jwk: JWK) => kid == null || jwk["kid"] === kid;
	if (JWS_FAMILY_RSA.includes(alg) || JWS_FAMILY_EC.includes(alg)) {
		// RSA or EC key matcher
		matches = (jwk) =>
			jwk["kty"] === kty &&
			useMatches(jwk) &&
			algMatches(jwk) &&
			kidMatches(jwk) &&
			(x5tS256 == null || matchesX5tS256(jwk, x5tS256));
	} else if (JWS_FAMILY_HMAC_SHA.includes(alg)) {
		// HMAC secret matcher
		matches = (jwk) => JWKUtil.isPrivate(jwk) && jwk["kty"] === kty && algMatches(jwk) && kidMatches(jwk);
	} else if (JWS_FAMILY_ED.includes(alg)) {
		const curves = curvesForJwsAlgorithm(alg);
		matches = (jwk) =>
			jwk["kty"] === kty &&
			useMatches(jwk) &&
			algMatches(jwk) &&
			kidMatches(jwk) &&
			(curves == null || curves.includes(jwk["crv"] as string));
	} else {
		return []; // Unsupported algorithm
	}

	const sanitizedJWKs: JWK[] = [];
	for (const jwk of jwkSet.keys.filter(matches)) {
		if (jwk["kty"] === "RSA" || jwk["kty"] === "EC" || jwk["kty"] === "OKP") {
			sanitizedJWKs.push(JWKUtil.toPublicJWK(jwk) as JWK);
			if (JWKUtil.isPrivate(jwk)) {
				sanitizedJWKs.push(jwk);
			}
		} else if (jwk["kty"] === "oct") {
			sanitizedJWKs.push(jwk);
		}
	}
	return sanitizedJWKs;
}

/**
 * The JWS verifier for one key (replaces the Nimbus Ed25519Verifier / RSASSAVerifier / ECDSAVerifier /
 * MACVerifier built from it).
 */
interface Verifier {
	jwk: JWK;
	key: Awaited<ReturnType<typeof JWKUtil.importKey>>;
}

/**
 * Nimbus JWSVerifier.verify via SignedJWT.verify: the verifier's own checks first (these throw a JOSEException),
 * then false for unprocessed critical header params, then the signature check.
 */
async function verify(jwt: JWT, verifier: Verifier): Promise<boolean> {
	const alg = jwt.header["alg"] as string;
	const kty = verifier.jwk["kty"];
	if (kty === "EC") {
		const supported = ECDSA_ALGORITHM_FOR_CURVE[verifier.jwk["crv"] as string];
		if (alg !== supported) {
			throw new JOSEException("Unsupported JWS algorithm " + alg + ", must be " + supported);
		}
	} else if (kty === "OKP") {
		if (alg !== "Ed25519" && alg !== "EdDSA") {
			throw new JOSEException("Ed25519Verifier requires alg=Ed25519 or alg=EdDSA in JWSHeader");
		}
	} else if (kty === "oct") {
		const minRequiredBitLength = MAC_MIN_SECRET_BITS[alg];
		if ((verifier.key as Uint8Array).length * 8 < minRequiredBitLength) {
			throw new JOSEException("The secret length for " + alg + " must be at least " + minRequiredBitLength + " bits");
		}
	}
	const crit = jwt.header["crit"];
	if (Array.isArray(crit) && crit.some((p) => !PROCESSED_CRITICAL_HEADER_PARAMS.includes(p as string))) {
		return false;
	}
	try {
		await compactVerify(jwt.parts.join("."), verifier.key, { algorithms: [alg] });
		return true;
	} catch (e) {
		if (e instanceof errors.JWSSignatureVerificationFailed) {
			return false;
		}
		// jose rejects some keys/inputs Nimbus accepts (e.g. RSA keys shorter than 2048 bits) - report like a
		// Nimbus JOSEException thrown by verify()
		throw new JOSEException((e as Error).message, { cause: e });
	}
}

export class ValidateRequestObjectSignature extends AbstractLenientJwksCondition {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_request_object", "client_public_jwks", "client"],
	};
	static override post: EnvironmentRequirements = { strings: ["request_object_signing_alg"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const requestObject = env.getString("authorization_request_object", "value") as string;
		const clientJwks = env.getObject("client_public_jwks") as JsonObject;

		try {
			const jwt = parseSignedJWT(requestObject);
			// parse leniently: skip keys the JOSE library cannot handle (e.g. unsupported curves
			// like Brainpool, or future PQ algorithms) so an unusable key elsewhere in the client's
			// set does not abort verification when a usable signing key is present; skipped keys are logged
			const jwkSet = this.parseJwksLenientlyLoggingSkips(JSON.stringify(clientJwks), "client");

			const client = env.getObject("client") as JsonObject;
			if (has(client, "request_object_signing_alg")) {
				//https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
				//request_object_signing_alg
				//All Request Objects from this Client MUST be rejected, if not signed with this algorithm.
				//The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used
				const expectedAlg = OIDFJSON.getString(client["request_object_signing_alg"]);
				const jwsAlgorithm = jwt.header["alg"] as string;
				if (jwsAlgorithm !== expectedAlg) {
					throw this.error(
						"Algorithm in JWT header does not match client request_object_signing_alg.",
						args("actual", jwsAlgorithm, "expected", expectedAlg),
					);
				}
			}

			const jwkKeys = selectJWSJwks(jwt.header, jwkSet);
			if (jwkKeys == null || jwkKeys.length === 0) {
				throw this.error(
					"Could not find any keys that can be used to verify this signature",
					args("requestObject", requestObject, "clientJwks", clientJwks),
				);
			}

			const newJwkSet: JsonObject = { keys: jwkKeys };
			const publicJwks = JWKUtil.getPublicJwksAsJsonObject(newJwkSet);

			// Record why each candidate key did not verify the signature. Kept until the end and only
			// reported if NO key works, so a usable key verifying does not produce noise about the others.
			const failedKeys: JsonArray = [];

			const headerAlg = jwt.header["alg"] as string;
			for (const jwkKey of jwkKeys) {
				let verifier: Verifier | null = null;
				try {
					if (jwkKey["kty"] === "OKP") {
						const publicKey = JWKUtil.toPublicJWK(jwkKey) as JWK;
						if ("Ed25519" === publicKey["crv"]) {
							verifier = {
								jwk: publicKey,
								key: await JWKUtil.importKey(publicKey, headerAlg === "Ed25519" ? "Ed25519" : "EdDSA"),
							};
						} else {
							this.recordFailedKey(
								failedKeys,
								jwkKey,
								"the JOSE library cannot verify with this key's curve ('" + String(publicKey["crv"]) + "')",
							);
						}
					} else if (jwkKey["kty"] === "RSA" || jwkKey["kty"] === "EC") {
						const publicKey = JWKUtil.toPublicJWK(jwkKey) as JWK;
						// like Nimbus' ECDSAVerifier, an EC key is bound to the algorithm of its curve; a mismatch with
						// the header alg is reported by verify()
						const keyAlg =
							publicKey["kty"] === "EC"
								? (ECDSA_ALGORITHM_FOR_CURVE[publicKey["crv"] as string] ?? headerAlg)
								: headerAlg;
						verifier = { jwk: publicKey, key: await JWKUtil.importKey(publicKey, keyAlg) };
					} else if (jwkKey["kty"] === "oct") {
						const secretKey = (await JWKUtil.importKey(jwkKey, headerAlg)) as Uint8Array;
						if (secretKey.length * 8 < 256) {
							throw new JOSEException("The secret length must be at least 256 bits");
						}
						verifier = { jwk: jwkKey, key: secretKey };
					}
				} catch (e) {
					// jose has no equivalent of some Nimbus verifiers (e.g. ES256K) and rejects some keys at import
					// time - both are reported like Nimbus failing to build a verifier
					this.recordFailedKey(
						failedKeys,
						jwkKey,
						"the JOSE library could not build a verifier for this key: " + (e as Error).message,
					);
				}
				if (verifier != null) {
					if (await verify(jwt, verifier)) {
						const alg = headerAlg;
						env.putString("request_object_signing_alg", alg);
						this.logSuccess(
							"Request object signature validated using a key in the client's JWKS " +
								"and using the client's registered request_object_signing_alg",
							args(
								"request_object_signing_alg",
								alg,
								"jwk",
								JSON.stringify(jwkKey),
								"keys",
								publicJwks,
								"request_object",
								requestObject,
							),
						);
						return env;
					} else {
						// failed to verify with this key, moving on - not a failure yet as it might pass a different key
						this.recordFailedKey(failedKeys, jwkKey, "the signature did not verify with this key");
					}
				}
			}

			// if we got here, it hasn't been verified by any key
			throw this.error(
				"Unable to verify request object signature based on client keys",
				args(
					"jwt_header",
					JSON.stringify(jwt.header),
					"keys",
					publicJwks,
					"failed_keys",
					failedKeys,
					"clientJwks",
					clientJwks,
					"requestObject",
					requestObject,
				),
			);
		} catch (e) {
			if (e instanceof JOSEException || e instanceof ParseException) {
				throw this.error("error validating request object signature", e);
			}
			throw e;
		}
	}

	private recordFailedKey(failedKeys: JsonArray, jwkKey: JWK, reason: string): void {
		const entry: JsonObject = {};
		entry["kid"] = (jwkKey["kid"] as string | undefined) ?? null;
		if (jwkKey["kty"] != null) {
			entry["kty"] = jwkKey["kty"] as string;
		}
		entry["reason"] = reason;
		failedKeys.push(entry);
	}
}
