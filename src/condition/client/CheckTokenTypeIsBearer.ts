import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckTokenTypeIsBearer extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const tokenType = env.getString("token_endpoint_response", "token_type");
		if (!tokenType) {
			throw this.error("Couldn't find token type");
		}

		if ("bearer" !== tokenType.toLowerCase()) {
			throw this.error("Token type is not bearer");
		}

		this.logSuccess("Token type is bearer");

		return env;
	}
}
