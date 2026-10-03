import { args, OIDFJSON, type JsonObject } from "../../framework/index.ts";
import { JWKUtil, ParseException } from "../../util/JWKUtil.ts";
import { getRequiredParams } from "../../util/nimbus/jwk.ts";
import { AbstractCompareJwks } from "./AbstractCompareJwks.ts";

export class VerifyNewJwksHasNewSigningKey extends AbstractCompareJwks {
	/**
	 * Returns the set of JSON objects that correspond the public key components of the input JSON key objects.
	 * The resulting key components include only the public key components, kty, and kid. All other information
	 * is removed so that key lists can be compared.
	 * The input JWK keys components must be valid components.
	 * @param inputKeys Set of JSON objects representing JWK key components (RSA, EC)
	 * @return Set of JSON objects that contains the public key components including kid, kty
	 * @throws ConditionError error when JWK components are invalid
	 */
	private getPubKeysWithKeyId(inputKeys: JsonObject[]): JsonObject[] {
		const out: JsonObject[] = [];
		for (const key of inputKeys) {
			try {
				const jwk = JWKUtil.parseJWK(JSON.stringify(key));
				const requiredParamsJson: JsonObject = getRequiredParams(jwk);
				requiredParamsJson["kid"] = (jwk["kid"] as string | undefined) ?? null;
				AbstractCompareJwks.addToSet(out, requiredParamsJson);
			} catch (e) {
				if (e instanceof ParseException) {
					throw this.error("Error parsing JWK key", e, args("key", key));
				}
				throw e;
			}
		}
		return out;
	}

	protected override compareJwks(originalSigningKeys: JsonObject[], latestSigningKeys: JsonObject[]): void {
		const origSigningPubKeys = this.getPubKeysWithKeyId(originalSigningKeys);
		const latestSigningPubKeys = this.getPubKeysWithKeyId(latestSigningKeys);
		const keysOnlyInNew = latestSigningPubKeys.filter((k) => !AbstractCompareJwks.setContains(origSigningPubKeys, k));
		if (keysOnlyInNew.length === 0) {
			throw this.error(
				"No new keys with 'use':'sig' (or no 'use') found",
				args("original_signing_keys", originalSigningKeys, "latest_signing_keys", latestSigningKeys),
			);
		}

		// for each new key, verify it is actually new
		keysOnlyInNew.forEach((newKeyToCheck) => {
			const kid = OIDFJSON.getString(newKeyToCheck["kid"]);

			const keysWithMatchingKids = originalSigningKeys.filter((mk) => OIDFJSON.getString(mk["kid"]) === kid);

			if (keysWithMatchingKids.length > 0) {
				throw this.error(
					"One of the new keys uses the same kid as one of the original keys",
					args("original_signing_keys", originalSigningKeys, "latest_signing_keys", latestSigningKeys, "bad_kid", kid),
				);
			}

			const kty = OIDFJSON.getString(newKeyToCheck["kty"]);
			let field: string;
			switch (kty) {
				case "RSA":
					field = "n";
					break;
				case "EC":
					field = "x";
					break; // it seems sufficient for 'x' to be the same, no need to check 'y'
				default:
					throw this.error("unknown key type '" + kty + "' found", args("jwk", newKeyToCheck));
			}

			const exponent = OIDFJSON.getString(newKeyToCheck[field]);
			const keysWithSameExponent = originalSigningKeys.filter(
				(mk) => mk[field] != null && OIDFJSON.getString(mk[field]) === exponent,
			);

			if (keysWithSameExponent.length > 0) {
				throw this.error(
					"One of the new keys uses the same exponent as one of the original keys",
					args(
						"original_signing_keys",
						originalSigningKeys,
						"latest_signing_keys",
						latestSigningKeys,
						"bad_" + field,
						exponent,
					),
				);
			}
		});

		this.logSuccess("Found new keys", args("new_signing_keys", keysOnlyInNew));
	}
}
