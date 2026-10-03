import {
	AbstractCondition,
	args,
	isJsonArray,
	isJsonObject,
	OIDFJSON,
	type Environment,
} from "../../framework/index.ts";

export abstract class AbstractCheckDistinctKeyIdValueInJWKs extends AbstractCondition {
	protected checkDistinctKeyIdValueInJWKs(env: Environment, envJWKsKey: string): Environment {
		const keys = env.getElementFromObject(envJWKsKey, "keys");

		if (keys == null) {
			throw this.error("keys entry not found in JWKs");
		}

		if (!isJsonArray(keys)) {
			throw this.error("keys entry in JWKs is not an array", args("keys", keys));
		}

		const keyIdSets = new Set<string>();
		for (const key of keys) {
			if (!isJsonObject(key)) {
				throw this.error("invalid key in JWKs, not a JSON object", args("key", key));
			}

			const keyIdElement = key["kid"];
			if (keyIdElement !== undefined) {
				const kid = OIDFJSON.getString(keyIdElement);
				if (keyIdSets.has(kid)) {
					throw this.error(
						"'kid' value is used more than once in " + envJWKsKey,
						args(
							"kid_duplicate",
							OIDFJSON.getString(keyIdElement),
							"keys",
							keys,
							"see",
							"https://bitbucket.org/openid/connect/issues/1127",
						),
					);
				}
				keyIdSets.add(kid);
			}
		}

		this.logSuccess(
			"Distinct 'kid' value in all keys of " + envJWKsKey,
			args("see", "https://bitbucket.org/openid/connect/issues/1127"),
		);
		return env;
	}
}
