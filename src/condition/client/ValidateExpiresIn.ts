import {
	AbstractCondition,
	args,
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ValidateExpiresIn extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["expires_in"] };

	override evaluate(env: Environment): Environment {
		const expiresIn = env.getObject("expires_in") as JsonObject;
		const je = expiresIn["expires_in"];
		// Java: getAsJsonPrimitive() throws IllegalStateException if not a primitive
		if (!isJsonPrimitive(je)) {
			throw this.error("expires_in is not a JSON primitive");
		}
		if (typeof je !== "number") {
			throw this.error("expires_in is not a number");
		}

		const n = OIDFJSON.getNumber(je);
		if (Math.trunc(n) <= 0) {
			// https://tools.ietf.org/html/rfc6749#appendix-A.14 technically allows a zero expires_in, but
			// returning a token that is already expires seems nonsensical
			throw this.error("expires_in must be positive");
		}
		if (Math.trunc(n) > 31536000) {
			throw this.error(
				"expires_in is unreasonably large (more than 1 year), this may indicate the value was incorrectly specified in milliseconds instead of seconds",
				args("expires_in", n),
			);
		}

		this.logSuccess("expires_in passed all validation checks", expiresIn);
		return env;
	}
}
