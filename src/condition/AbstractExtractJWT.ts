import { errors } from "jose";
import {
	AbstractCondition,
	args,
	isJsonArray,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type JsonObject,
} from "../framework/index.ts";
import { JOSEException } from "../util/JWEUtil.ts";
import { ParseException } from "../util/JWKUtil.ts";
import { JWTUtil } from "../util/JWTUtil.ts";

export abstract class AbstractExtractJWT extends AbstractCondition {
	/**
	 * Java overloads extractJWT(env, key, path, dstPath) and extractJWT(env, key, path, dstPath, client,
	 * privateJwksWithEncKeys). Async because decrypting the JWT (when it is encrypted) uses jose.
	 */
	protected async extractJWT(
		env: Environment,
		key: string,
		path: string,
		dstPath: string,
		client: JsonObject | null = null,
		privateJwksWithEncKeys: JsonObject | null = null,
	): Promise<Environment> {
		// Remove any old token
		env.removeObject(dstPath);

		const tokenElement = env.getElementFromObject(key, path);
		if (tokenElement == null || isJsonObject(tokenElement) || isJsonArray(tokenElement)) {
			throw this.error("Couldn't find " + path + " in " + key);
		}

		const tokenString = OIDFJSON.getString(tokenElement);

		try {
			const jwtAsJsonObject: JsonObject | null = await JWTUtil.jwtStringToJsonObjectForEnvironment(
				tokenString,
				client,
				privateJwksWithEncKeys,
			);
			if (jwtAsJsonObject == null) {
				throw this.error("Couldn't parse " + dstPath + " from " + key + " as a JWT", args(dstPath, tokenString));
			}

			// save the parsed token
			env.putObject(dstPath, jwtAsJsonObject);

			this.logSuccess("Found and parsed the " + dstPath + " from " + key, jwtAsJsonObject);

			return env;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Couldn't parse " + dstPath + " from " + key + " as a JWT", e, args(dstPath, tokenString));
			}
			if (e instanceof JOSEException || e instanceof errors.JOSEError) {
				throw this.error("Decrypting " + dstPath + " from " + key + " failed", e, args(dstPath, tokenString));
			}
			throw e;
		}
	}
}
