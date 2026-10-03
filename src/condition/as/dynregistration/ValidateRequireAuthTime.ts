import {
	args,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 *  require_auth_time
 *  OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED.
 *  It is REQUIRED when the value is true. (If this is false, the auth_time Claim can still be
 *  dynamically requested as an individual Claim for the ID Token using the claims request
 *  parameter described in Section 5.5.1 of OpenID Connect Core 1.0 [OpenID.Core].) If omitted,
 *  the default value is false.
 *
 */
export class ValidateRequireAuthTime extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		try {
			const requireAuthTime = this.getRequireAuthTime();
			if (requireAuthTime == null) {
				this.logSuccess("require_auth_time is not set");
				return env;
			} else {
				this.logSuccess("require_auth_time is encoded as a boolean", args("require_auth_time", requireAuthTime));
				return env;
			}
		} catch (ex) {
			if (!(ex instanceof UnexpectedJsonTypeException)) {
				throw ex;
			}
			throw this.error(
				"require_auth_time is not encoded as a boolean",
				args("require_auth_time", this.client["require_auth_time"]),
			);
		}
	}
}
