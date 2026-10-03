import {
	AbstractCondition,
	args,
	has,
	isJsonArray,
	isJsonObject,
	OIDFJSON,
	type Environment,
} from "../../framework/index.ts";

export abstract class AbstractCheckForKeyIdinJWKs extends AbstractCondition {
	protected checkForKeyIdInJWKs(env: Environment, envJWKsKey: string): Environment {
		const keys = env.getElementFromObject(envJWKsKey, "keys");
		if (keys == null) {
			throw this.error("keys entry not found in JWKs");
		}
		if (!isJsonArray(keys)) {
			throw this.error("keys entry in JWKs is not an array", args("keys", keys));
		}

		for (const key of keys) {
			if (!isJsonObject(key)) {
				throw this.error("invalid key in JWKs, not a JSON object", args("key", key));
			}

			const keyObj = key;
			if (!has(keyObj, "kid") || OIDFJSON.getString(keyObj["kid"]).trim() === "") {
				throw this.error("kid not found in key", args("key", key));
			}
		}

		this.logSuccess("All keys contain kids");

		return env;
	}
}
