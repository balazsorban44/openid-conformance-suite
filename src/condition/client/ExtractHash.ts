import {
	AbstractCondition,
	UnexpectedTypeException,
	type Environment,
	type JsonObject,
} from "../../framework/index.ts";

export abstract class ExtractHash extends AbstractCondition {
	extractHash(env: Environment, hashName: string, envName: string): Environment {
		env.removeObject(envName);

		if (!env.containsObject("id_token")) {
			throw this.error("Couldn't find parsed ID token");
		}

		let hash: string | null;
		try {
			hash = env.getString("id_token", "claims." + hashName);
		} catch (e) {
			// Java: catch (IllegalArgumentException e); Environment.UnexpectedTypeException extends it
			if (e instanceof UnexpectedTypeException) {
				throw this.error(hashName + " in ID token is not a string");
			}
			throw e;
		}

		if (hash == null) {
			throw this.error("Couldn't find " + hashName + " in ID token");
		}

		const alg = env.getString("id_token", "header.alg");
		if (alg == null) {
			throw this.error("Couldn't find algorithm in ID token header");
		}

		const outData: JsonObject = {};
		outData[hashName] = hash;
		outData["alg"] = alg;

		env.putObject(envName, outData);

		this.logSuccess("Extracted " + hashName + " from ID Token", outData);

		return env;
	}
}
