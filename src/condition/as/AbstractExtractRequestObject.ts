import { errors } from "jose";
import { AbstractCondition, args, type Environment } from "../../framework/index.ts";
import { JOSEException } from "../../util/JWEUtil.ts";
import { JWTUtil, ParseException } from "../../util/JWTUtil.ts";

export abstract class AbstractExtractRequestObject extends AbstractCondition {
	async processRequestObjectString(requestObjectString: string | null, env: Environment): Promise<Environment> {
		if (!requestObjectString) {
			throw this.error("Could not find request object in request parameters");
		}

		try {
			const client = env.getObject("client");
			const serverEncKeys = env.getObject("server_encryption_keys");
			const jsonObjectForJwt = await JWTUtil.jwtStringToJsonObjectForEnvironment(
				requestObjectString,
				client,
				serverEncKeys,
			);

			if (jsonObjectForJwt == null) {
				throw this.error("Couldn't extract request object", args("request", requestObjectString));
			}
			env.putObject("authorization_request_object", jsonObjectForJwt);

			this.logSuccess("Parsed request object", args("request_object", jsonObjectForJwt));

			return env;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Couldn't parse request object: " + e.message, e, args("request", requestObjectString));
			}
			if (e instanceof JOSEException || e instanceof errors.JOSEError) {
				throw this.error("Request object decryption failed", e, args("request", requestObjectString));
			}
			throw e;
		}
	}
}
