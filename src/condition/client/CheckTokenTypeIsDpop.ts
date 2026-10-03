import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckTokenTypeIsDpop extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const tokenType = env.getString("token_endpoint_response", "token_type");
		if (!tokenType) {
			throw this.error("Couldn't find token type");
		}

		if ("dpop" !== tokenType.toLowerCase()) {
			throw this.error("Token type is not DPoP");
		}

		this.logSuccess("Token type is DPoP");

		return env;
	}
}
