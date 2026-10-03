import { OIDFJSON, type JsonObject } from "../framework/json.ts";
import { JWEUtil } from "./JWEUtil.ts";
import { JWKUtil, type JWK } from "./JWKUtil.ts";
import { JWE_FAMILY_SYMMETRIC } from "./nimbus/algorithms.ts";
import { ParseException } from "./nimbus/errors.ts";
import { claimsSetToJSONObject, parseJWT as nimbusParseJWT, type JWT } from "./nimbus/jwt.ts";
import { nimbusParseJsonObject } from "./nimbus/json.ts";

// The Nimbus emulation lives in ./nimbus/; re-exported here for the ported code that imports it from JWTUtil.
export type { JWT } from "./nimbus/jwt.ts";
export { ParseException } from "./nimbus/errors.ts";

export class JWTUtil {
	// 2024-01-01T00:00:00Z in seconds — any valid iat should be at least this recent
	private static readonly MIN_REASONABLE_TIMESTAMP = 1704067200;
	private static readonly SECONDS_PER_YEAR = 365 * 24 * 60 * 60;
	private static readonly CLOCK_SKEW_SECONDS = 5 * 60; // 5 minutes

	/**
	 * Validates an 'iat' (Issued At) claim value per RFC 7519.
	 * Checks that the value is a number, not before 2024 (catches millisecond timestamps),
	 * and not in the future (with 5 minutes clock skew tolerance).
	 *
	 * @param iat the raw claim value from the JWT payload (may be null)
	 * @return the validated timestamp in seconds
	 * @throws Error (IllegalArgumentException) if the value is missing, not a number, or out of range
	 */
	static validateIatClaim(iat: unknown): number {
		if (iat == null) {
			throw new Error("Missing 'iat' claim");
		}
		if (typeof iat !== "number") {
			throw new Error("'iat' claim is not a number");
		}
		const iatValue = Math.trunc(iat);
		if (iatValue < JWTUtil.MIN_REASONABLE_TIMESTAMP) {
			throw new Error(
				"'iat' claim value " +
					iatValue +
					" is too far in the past (this may indicate the value is not a unix timestamp in seconds)",
			);
		}
		const nowSeconds = Math.floor(Date.now() / 1000);
		if (iatValue > nowSeconds + JWTUtil.CLOCK_SKEW_SECONDS) {
			throw new Error("'iat' claim value " + iatValue + " is in the future (now: " + nowSeconds + ")");
		}
		return iatValue;
	}

	/**
	 * Validates an 'nbf' (Not Before) claim value per RFC 7519.
	 * Checks that the value is a number, not before 2024 (catches millisecond timestamps and
	 * epoch-default bugs), and not in the future (with 5 minutes clock skew tolerance).
	 *
	 * @param nbf the raw claim value from the JWT payload (may be null)
	 * @return the validated timestamp in seconds, or -1 if nbf is null (not present)
	 * @throws Error (IllegalArgumentException) if the value is not a number, out of range, or in the future
	 */
	static validateNbfClaim(nbf: unknown): number {
		if (nbf == null) {
			return -1;
		}
		if (typeof nbf !== "number") {
			throw new Error("'nbf' claim is not a number");
		}
		const nbfValue = Math.trunc(nbf);
		if (nbfValue < JWTUtil.MIN_REASONABLE_TIMESTAMP) {
			throw new Error(
				"'nbf' claim value " +
					nbfValue +
					" is too far in the past (this may indicate the value is not a unix timestamp in seconds)",
			);
		}
		const nowSeconds = Math.floor(Date.now() / 1000);
		if (nbfValue > nowSeconds + JWTUtil.CLOCK_SKEW_SECONDS) {
			throw new Error("'nbf' claim value " + nbfValue + " is in the future (now: " + nowSeconds + ")");
		}
		return nbfValue;
	}

	/**
	 * Validates an 'exp' (Expiration Time) claim value per RFC 7519.
	 * Checks that the value is a number, not more than 50 years in the future (catches millisecond timestamps),
	 * and not in the past (with 5 minutes clock skew tolerance).
	 *
	 * @param exp the raw claim value from the JWT payload (may be null)
	 * @return the validated timestamp in seconds, or -1 if exp is null (not present)
	 * @throws Error (IllegalArgumentException) if the value is not a number, out of range, or expired
	 */
	static validateExpClaim(exp: unknown): number {
		if (exp == null) {
			return -1;
		}
		if (typeof exp !== "number") {
			throw new Error("'exp' claim is not a number");
		}
		const expValue = Math.trunc(exp);
		const nowSeconds = Math.floor(Date.now() / 1000);
		const maxTimestamp = nowSeconds + 50 * JWTUtil.SECONDS_PER_YEAR;
		if (expValue > maxTimestamp) {
			throw new Error(
				"'exp' claim value " +
					expValue +
					" is too far in the future (this may indicate the value is not a unix timestamp in seconds)",
			);
		}
		if (expValue < nowSeconds - JWTUtil.CLOCK_SKEW_SECONDS) {
			throw new Error("'exp' claim value " + expValue + " indicates the JWT has expired (now: " + nowSeconds + ")");
		}
		return expValue;
	}

	/**
	 * wrapper for Nimbus JWTParser
	 * just in case we want to override something one day
	 *
	 * Returns a {@link JWT} (replaces Nimbus `JWT`); the header and payload are parsed with Nimbus' rules and error
	 * messages but nothing is verified or decrypted.
	 * @param jwtAsString
	 * @return
	 * @throws ParseException
	 */
	static parseJWT(jwtAsString: string): JWT {
		JWTUtil.validateJwtContainsOnlyAllowedCharacters(jwtAsString);
		const jwt = nimbusParseJWT(jwtAsString);
		return jwt;
	}

	/** @throws ParseException */
	static validateJwtContainsOnlyAllowedCharacters(jwt: string): void {
		// the allowed characters is base64url plus '.'
		const regex = /^[.a-zA-Z0-9_-]$/;
		// UPSTREAM: Java iterates UTF-16 chars, so a non-BMP character is reported as its high surrogate
		for (let i = 0; i < jwt.length; i++) {
			const character = jwt.charAt(i);
			if (!regex.test(character)) {
				throw new ParseException(
					`The jwt is invalid because at index ${i} it contains the character ${character} that is neither a '.' nor one permitted in unpadded base64url`,
					0,
				);
			}
		}
	}

	/**
	 * Also see jwtStringToJsonObjectForEnvironment
	 *
	 * Replaces `jwtClaimsSetAsJsonObject(JWT)`: the claims as Nimbus' `JWTClaimsSet.toJSONObject(true)` renders them
	 * (e.g. a single element `aud` array becomes a string, `exp`/`iat`/`nbf` are truncated to whole seconds, a
	 * numeric `sub` becomes a string, duplicate member names are rejected).
	 * @param jwt
	 * @return
	 * @throws ParseException
	 */
	static jwtClaimsSetAsJsonObject(jwt: JWT): JsonObject {
		// This code does multiple conversions to JSON; we could just call 'JsonParser.parseString' here, however
		// that seems to result in the unit test failing as we no longer detect JSON payloads that have the same
		// claim more than once.
		const jsonPayload = jwt.payload;
		if (jsonPayload == null) {
			throw new ParseException("Failed to get JWT payload as a string", 0);
		}

		const claims = claimsSetToJSONObject(nimbusParseJsonObject(jsonPayload));
		return claims;
	}

	/**
	 * Also see jwtStringToJsonObjectForEnvironment
	 * Note: Nimbusds will always remove null values from JWT headers
	 * @param jwt
	 * @return
	 */
	static jwtHeaderAsJsonObject(jwt: JWT): JsonObject {
		const header = structuredClone(jwt.header);
		return header;
	}

	/**
	 * Parses the JWT and returns a JsonObject with value, header and claims entries
	 *
	 * The single-argument form is synchronous. The three-argument form (use if the JWT may be encrypted, e.g an
	 * encrypted request object) is async because decryption uses jose; it returns a Promise.
	 *
	 * @param client Client object containing client_secret, required if symmetric encryption used
	 * @param privateJwksWithEncKeys Key for decryption, if encryption used
	 * @return may return null if decryption fails
	 * @throws ParseException
	 */
	static jwtStringToJsonObjectForEnvironment(jwtAsString: string): JsonObject;
	static jwtStringToJsonObjectForEnvironment(
		jwtAsString: string,
		client: JsonObject | null | undefined,
		privateJwksWithEncKeys: JsonObject | null | undefined,
	): Promise<JsonObject>;
	static jwtStringToJsonObjectForEnvironment(
		jwtAsString: string,
		...rest: [] | [JsonObject | null | undefined, JsonObject | null | undefined]
	): JsonObject | Promise<JsonObject> {
		if (rest.length === 0) {
			const token = JWTUtil.parseJWT(jwtAsString);

			if (token.type === "encrypted") {
				throw new ParseException("EncryptedJWT found, which this test currently doesn't support", 0);
			}
			const header = JWTUtil.jwtHeaderAsJsonObject(token);
			const claims = JWTUtil.jwtClaimsSetAsJsonObject(token);

			return JWTUtil.createJsonObjectForEnvironment(jwtAsString, header, claims);
		}
		return JWTUtil.jwtStringToJsonObjectForEnvironmentMaybeEncrypted(jwtAsString, rest[0], rest[1]);
	}

	private static createJsonObjectForEnvironment(jwtString: string, header: JsonObject, claims: JsonObject): JsonObject {
		const jsonObject: JsonObject = {};
		jsonObject["value"] = jwtString;
		jsonObject["header"] = header;
		jsonObject["claims"] = claims;
		return jsonObject;
	}

	private static async jwtStringToJsonObjectForEnvironmentMaybeEncrypted(
		jwtAsString: string,
		client: JsonObject | null | undefined,
		privateJwksWithEncKeys: JsonObject | null | undefined,
	): Promise<JsonObject> {
		const token = JWTUtil.parseJWT(jwtAsString);
		if (token.type === "encrypted") {
			const encryptedJWT = token;
			const jweHeader = JWTUtil.jwtHeaderAsJsonObject(token);
			const alg = encryptedJWT.header["alg"] as string;
			let decryptionKey: JWK | null = null;
			if (JWE_FAMILY_SYMMETRIC.includes(alg)) {
				if (client == null) {
					throw new ParseException("A client secret is required to decrypt this JWT", 0);
				}
				const client_secret = OIDFJSON.getString(client["client_secret"]);
				if (client_secret == null) {
					throw new ParseException("A client secret is required to decrypt this JWT", 0);
				}
				decryptionKey = JWEUtil.createSymmetricJWKForAlgAndSecret(
					client_secret,
					alg,
					encryptedJWT.header["enc"] as string,
					null,
				);
			} else {
				if (privateJwksWithEncKeys == null) {
					throw new ParseException(
						"No suitable key for decrypting this JWT was provided in the test configuration. A private key of the correct key type with 'use': 'enc' and other matching properties is required.",
						0,
					);
				}
				const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(privateJwksWithEncKeys));
				const kid = encryptedJWT.header["kid"];
				decryptionKey = JWEUtil.selectAsymmetricKeyForEncryption(jwkSet, alg, typeof kid === "string" ? kid : null);
				if (decryptionKey == null) {
					throw new ParseException(
						"No suitable key for decrypting this JWT was provided in the test configuration. A private key of the correct key type with 'use': 'enc' and other matching properties is required.",
						0,
					);
				}
			}
			const decrypter = JWEUtil.createDecrypter(alg, decryptionKey);
			const decryptedJwt = Buffer.from(await decrypter.decrypt(encryptedJWT.serialized)).toString("utf8");
			try {
				JWTUtil.validateJwtContainsOnlyAllowedCharacters(decryptedJwt);
			} catch (e) {
				if (!(e instanceof ParseException)) {
					throw e;
				}
				throw new ParseException("The JWE has been decrypted. " + e.message, 0);
			}
			const out = JWTUtil.jwtStringToJsonObjectForEnvironment(decryptedJwt);
			out["jwe_header"] = jweHeader;
			return out;
		} else {
			const header = JWTUtil.jwtHeaderAsJsonObject(token);
			const claims = JWTUtil.jwtClaimsSetAsJsonObject(token);
			return JWTUtil.createJsonObjectForEnvironment(jwtAsString, header, claims);
		}
	}
}
