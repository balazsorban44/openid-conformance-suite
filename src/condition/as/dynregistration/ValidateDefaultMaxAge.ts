import {
	args,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 *  default_max_age
 *  OPTIONAL. Default Maximum Authentication Age. Specifies that the End-User MUST be actively
 *  authenticated if the End-User was authenticated longer ago than the specified number of seconds.
 *  The max_age request parameter overrides this default value. If omitted, no default
 *  Maximum Authentication Age is specified.
 *
 */
export class ValidateDefaultMaxAge extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		try {
			const defaultMaxAge = this.getDefaultMaxAge();
			if (defaultMaxAge == null) {
				this.logSuccess("default_max_age is not set");
				return env;
			} else {
				this.logSuccess("default_max_age is encoded as a number", args("default_max_age", defaultMaxAge));
				return env;
			}
		} catch (ex) {
			if (!(ex instanceof UnexpectedJsonTypeException)) {
				throw ex;
			}
			throw this.error(
				"default_max_age is not encoded as a number",
				args("default_max_age", this.client["default_max_age"]),
			);
		}
	}
}
