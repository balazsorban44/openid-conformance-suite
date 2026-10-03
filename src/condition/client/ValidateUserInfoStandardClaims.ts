import { type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractValidateOpenIdStandardClaims } from "./AbstractValidateOpenIdStandardClaims.ts";

export class ValidateUserInfoStandardClaims extends AbstractValidateOpenIdStandardClaims {
	static override pre: EnvironmentRequirements = { required: ["userinfo"] };

	override evaluate(env: Environment): Environment {
		const userInfo = env.getObject("userinfo") as JsonObject;

		const result = this.createObjectValidator(null, this.STANDARD_CLAIMS).isValid(userInfo);

		env.putObject("userinfo_unknown_claims", this.unknownClaims);

		if (result) {
			this.logSuccess("Userinfo is valid");
		} else {
			throw this.error("Userinfo is not valid");
		}

		return env;
	}
}
