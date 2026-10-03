import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { ParseException } from "../../util/JWTUtil.ts";
import { parseSignedJWT } from "../../util/nimbus/jwt.ts";

export class ValidateUserInfoSigningAlgIsRS256 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["userinfo_object"] };

	override evaluate(env: Environment): Environment {
		const userInfoObj = env.getString("userinfo_object", "value") as string;

		try {
			// translate stored items into nimbus objects
			const jwt = parseSignedJWT(userInfoObj);
			const alg = jwt.header["alg"] as string;

			if (alg !== "RS256") {
				throw this.error(
					"userinfo response must be signed with RS256 as requested in the client registration",
					args("alg", alg),
				);
			}

			this.logSuccess("userinfo response is signed with RS256", args("alg", alg));
			return env;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Error parsing userinfo response", e);
			}
			throw e;
		}
	}
}
