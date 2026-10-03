import {
	AbstractCondition,
	args,
	ConditionResult,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class ValidateRequestObjectIat extends AbstractCondition {
	private timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	static override pre: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override evaluate(env: Environment): Environment {
		const now = Date.now(); // Instant, in epoch milliseconds

		const iat = env.getLong("authorization_request_object", "claims.iat");

		if (iat == null) {
			this.log(args("msg", "Request object does not contain an 'iat' claim", "result", ConditionResult.INFO));
		} else {
			if (now + this.timeSkewMillis < iat * 1000) {
				throw this.error(
					"Token issued in the future, 'iat' claim value is in the future",
					args("issued-at", new Date(iat * 1000), "now", new Date(now)),
				);
			}

			if (now - 24 * 60 * 60 * 1000 > iat * 1000) {
				throw this.error(
					"'iat' is more than 1 day in the past",
					args("issued-at", new Date(iat * 1000), "now", new Date(now)),
				);
			}
		}

		this.logSuccess("iat claim is valid", args("iat", iat));

		return env;
	}
}
