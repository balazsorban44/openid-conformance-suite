import {
	AbstractCondition,
	args,
	has,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
	type JsonValue,
} from "../../framework/index.ts";

/**
 * Compare the claims between two id tokens, at least one of which was issued from the refresh token grant
 *
 * Implements checks as per:
 *
 * https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
 */
export class CompareIdTokenClaims extends AbstractCondition {
	private static readonly CLAIM_AUTH_TIME = "auth_time";
	private static readonly CLAIM_IAT = "iat";
	private static readonly CLAIM_AZP = "azp";
	private static readonly CLAIM_AUD = "aud";

	static override pre: EnvironmentRequirements = { required: ["first_id_token", "second_id_token"] };

	override evaluate(env: Environment): Environment {
		const firstIdToken = (env.getObject("first_id_token") as JsonObject)["claims"] as JsonObject;
		const secondIdToken = (env.getObject("second_id_token") as JsonObject)["claims"] as JsonObject;

		const valuesForLog: JsonObject = {};
		this.ensureClaimsExistAndAreEqual(firstIdToken, secondIdToken, "iss", valuesForLog);
		this.ensureClaimsExistAndAreEqual(firstIdToken, secondIdToken, "sub", valuesForLog);
		this.checkIssuedAt(firstIdToken, secondIdToken, valuesForLog);
		this.checkAud(firstIdToken, secondIdToken, valuesForLog);
		this.checkAuthTime(firstIdToken, secondIdToken, valuesForLog);
		this.checkAzp(firstIdToken, secondIdToken, valuesForLog);

		this.logSuccess("Validated id token claims successfully", valuesForLog);
		return env;
	}

	/**
	 * its azp Claim Value MUST be the same as in the ID Token issued when the original authentication occurred;
	 * if no azp Claim was present in the original ID Token, one MUST NOT be present in the new ID Token
	 * @param firstIdToken
	 * @param secondIdToken
	 */
	private checkAzp(firstIdToken: JsonObject, secondIdToken: JsonObject, valuesForLog: JsonObject): void {
		const CLAIM_AZP = CompareIdTokenClaims.CLAIM_AZP;
		if (!has(firstIdToken, CLAIM_AZP)) {
			if (has(secondIdToken, CLAIM_AZP)) {
				throw this.error(
					"Second id token cannot contain an azp claim because the initial id token does not have an azp claim",
				);
			}
		}
		if (!has(firstIdToken, CLAIM_AZP) && !has(secondIdToken, CLAIM_AZP)) {
			valuesForLog[CLAIM_AZP] = "Id tokens do not contain " + CLAIM_AZP + " claims";
			return;
		}
		const claim1 = firstIdToken[CLAIM_AZP] ?? null;
		const claim2 = secondIdToken[CLAIM_AZP] ?? null;
		if (claim1 !== claim2) {
			throw this.error(CLAIM_AZP + " claims are not the same", args("claim1", claim1, "claim2", claim2));
		}
		const values: JsonObject = {};
		values["first"] = OIDFJSON.getString(claim1);
		values["second"] = OIDFJSON.getString(claim2);
		values["note"] = "Values are expected to be equal";
		valuesForLog[CLAIM_AZP] = values;
	}

	/**
	 * if the ID Token contains an auth_time Claim,
	 * its value MUST represent the time of the original authentication
	 * - not the time that the new ID token is issued,
	 * TODO what if the second id token contains an auth_time claim but not the first id token
	 * @param firstIdToken
	 * @param secondIdToken
	 */
	private checkAuthTime(firstIdToken: JsonObject, secondIdToken: JsonObject, valuesForLog: JsonObject): void {
		const CLAIM_AUTH_TIME = CompareIdTokenClaims.CLAIM_AUTH_TIME;
		if (!has(secondIdToken, CLAIM_AUTH_TIME)) {
			return;
		}
		const claim1 = firstIdToken[CLAIM_AUTH_TIME] ?? null;
		const claim2 = secondIdToken[CLAIM_AUTH_TIME] ?? null;
		if (claim2 !== claim1) {
			throw this.error("auth_time claims are not the same", args("claim1", claim1, "claim2", claim2));
		}
		const values: JsonObject = {};
		values["first"] = OIDFJSON.getNumber(claim1);
		values["second"] = OIDFJSON.getNumber(claim2);
		values["note"] = "Values are expected to be equal";
		valuesForLog[CLAIM_AUTH_TIME] = values;
	}

	/**
	 * its iat Claim MUST represent the time that the new ID Token is issued,
	 * @param firstIdToken
	 * @param secondIdToken
	 */
	private checkIssuedAt(firstIdToken: JsonObject, secondIdToken: JsonObject, valuesForLog: JsonObject): void {
		const CLAIM_IAT = CompareIdTokenClaims.CLAIM_IAT;
		if (!has(firstIdToken, CLAIM_IAT)) {
			throw this.error("Initial id token does not contain an " + CLAIM_IAT + " claim", args("claimName", CLAIM_IAT));
		}
		if (!has(secondIdToken, CLAIM_IAT)) {
			throw this.error("Second id token does not contain an " + CLAIM_IAT + " claim", args("claimName", CLAIM_IAT));
		}
		const claim1 = firstIdToken[CLAIM_IAT];
		const claim2 = secondIdToken[CLAIM_IAT];
		if (claim1 === claim2) {
			throw this.error(
				"iat for the second id token MUST represent the time that the new ID Token is issued, " +
					"cannot be the same as the initial id token",
				args("First iat", claim1, "Second iat", claim2),
			);
		}
		const values: JsonObject = {};
		values["first"] = OIDFJSON.getNumber(claim1);
		values["second"] = OIDFJSON.getNumber(claim2);
		values["note"] = "Values are expected to be different";
		valuesForLog[CLAIM_IAT] = values;
	}

	private ensureClaimsExistAndAreEqual(
		firstIdToken: JsonObject,
		secondIdToken: JsonObject,
		claimName: string,
		valuesForLog: JsonObject,
	): void {
		if (!has(firstIdToken, claimName)) {
			throw this.error("Initial id token does not contain a " + claimName + " claim", args("claimName", claimName));
		}
		if (!has(secondIdToken, claimName)) {
			throw this.error("Second id token does not contain a " + claimName + " claim", args("claimName", claimName));
		}
		const claim1 = firstIdToken[claimName];
		const claim2 = secondIdToken[claimName];
		if (claim1 !== claim2) {
			throw this.error("Claim values are not the same", args("claim1", claim1, "claim2", claim2));
		}
		const values: JsonObject = {};
		values["first"] = OIDFJSON.getString(claim1);
		values["second"] = OIDFJSON.getString(claim2);
		values["note"] = "Values are expected to be equal";
		valuesForLog[claimName] = values;
	}

	private checkAud(firstIdToken: JsonObject, secondIdToken: JsonObject, valuesForLog: JsonObject): void {
		const CLAIM_AUD = CompareIdTokenClaims.CLAIM_AUD;
		if (!has(firstIdToken, CLAIM_AUD)) {
			throw this.error("Initial id token does not contain an " + CLAIM_AUD + " claim", args("claimName", CLAIM_AUD));
		}
		if (!has(secondIdToken, "aud")) {
			throw this.error("Second id token does not contain an " + CLAIM_AUD + " claim", args("claimName", CLAIM_AUD));
		}
		const values: JsonObject = {};

		if (Array.isArray(firstIdToken[CLAIM_AUD])) {
			const claim1 = firstIdToken[CLAIM_AUD] as JsonArray;
			const claim2 = secondIdToken[CLAIM_AUD] as JsonArray;
			values["first"] = claim1;
			values["second"] = claim2;

			const claim1AudSet = new Set<string>();
			claim1.forEach((e: JsonValue) => claim1AudSet.add(OIDFJSON.getString(e)));

			const claim2AudSet = new Set<string>();
			claim2.forEach((e: JsonValue) => claim2AudSet.add(OIDFJSON.getString(e)));

			if (claim1AudSet.size !== claim2AudSet.size || [...claim1AudSet].some((a) => !claim2AudSet.has(a))) {
				throw this.error(
					"aud Claim Value MUST be the same as in the ID Token issued when the original authentication occurred",
					args("First aud", claim1, "Second aud", claim2),
				);
			}
		} else {
			const claim1 = firstIdToken[CLAIM_AUD];
			const claim2 = secondIdToken[CLAIM_AUD];
			values["first"] = OIDFJSON.getString(claim1);
			values["second"] = OIDFJSON.getString(claim2);
			if (claim1 !== claim2) {
				throw this.error(
					"aud Claim Value MUST be the same as in the ID Token issued when the original authentication occurred",
					args("First aud", claim1, "Second aud", claim2),
				);
			}
		}

		values["note"] = "Values are expected to be equal";
		valuesForLog[CLAIM_AUD] = values;
	}
}
