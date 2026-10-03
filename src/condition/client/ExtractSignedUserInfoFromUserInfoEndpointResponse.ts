import {
	args,
	deepCopy,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractExtractJWT } from "../AbstractExtractJWT.ts";
import { ParseException } from "../../util/JWKUtil.ts";
import { JWTUtil } from "../../util/JWTUtil.ts";

const USERINFO_ENDPOINT_RESPONSE = "userinfo_endpoint_response_full";

export class ExtractSignedUserInfoFromUserInfoEndpointResponse extends AbstractExtractJWT {
	static override pre: EnvironmentRequirements = { required: [USERINFO_ENDPOINT_RESPONSE] };
	static override post: EnvironmentRequirements = { required: ["userinfo", "userinfo_object"] };

	override evaluate(env: Environment): Environment {
		// Remove any old token
		env.removeObject("userinfo");

		const userInfoJws = env.getString(USERINFO_ENDPOINT_RESPONSE, "body");

		try {
			// UPSTREAM: a missing body is not checked for (Java throws a NullPointerException)
			const jwtAsJsonObject = JWTUtil.jwtStringToJsonObjectForEnvironment(userInfoJws as string);

			// save the parsed token
			env.putObject("userinfo_object", jwtAsJsonObject);

			// deepcopy to avoid modifying userinfo_object
			const userinfo = deepCopy(jwtAsJsonObject["claims"] as JsonObject);

			// this list doesn't contain 'sub' as sub is also a standard claim in userinfo
			const jwtClaims = ["iss", "aud", "exp", "nbf", "iat", "jti"];

			// the JWT standard claims aren't part of the userinfo response (apart from 'sub'), so remove them
			for (const claim of jwtClaims) {
				delete userinfo[claim];
			}

			env.putObject("userinfo", userinfo);

			this.logSuccess("Found and parsed the userinfo from " + USERINFO_ENDPOINT_RESPONSE, jwtAsJsonObject);

			return env;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error(
					"Couldn't parse the " + USERINFO_ENDPOINT_RESPONSE + " as a JWT",
					e,
					args(USERINFO_ENDPOINT_RESPONSE, userInfoJws),
				);
			}
			throw e;
		}
	}
}
