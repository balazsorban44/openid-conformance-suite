import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class VerifyIdTokenSubConsistentHybridFlow extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_id_token", "token_endpoint_id_token"],
	};

	override evaluate(env: Environment): Environment {
		const subAuth = env.getString("authorization_endpoint_id_token", "claims.sub");
		const subToken = env.getString("token_endpoint_id_token", "claims.sub");

		if (subAuth !== subToken) {
			throw this.error(
				'"sub" in authorization endpoint id_token doesn\'t match with "sub" in token endpoint id_token',
				args("sub_auth_endpoint", subAuth, "sub_token_endpoint", subToken),
			);
		}

		this.logSuccess(
			"authorization endpoint and token endpoint id_token have same sub",
			args("sub_auth_endpoint", subAuth, "sub_token_endpoint", subToken),
		);
		return env;
	}
}
