import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class CheckForClientAssertionJtiReuse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client_assertion"] };

	override evaluate(env: Environment): Environment {
		const clientAssertion = env.getObject("client_assertion");
		if (clientAssertion == null) {
			throw this.error("missing client_assertion");
		}

		const jtiEl = env.getElementFromObject("client_assertion", "claims.jti");
		if (jtiEl == null) {
			throw this.error("jti claim missing on client_assertion", args("client_assertion", clientAssertion));
		}
		const jti = OIDFJSON.getString(jtiEl);

		const key = "client_assertion_jti_" + jti;
		if (env.getString(key) != null) {
			throw this.error(
				"Detected reuse of client_assertion JWT for jti=" + jti,
				args("client_assertion", clientAssertion),
			);
		}

		env.putString(key, jti);
		this.logSuccess("No reuse found for client_assertion JWT for jti=" + jti);

		return env;
	}
}
