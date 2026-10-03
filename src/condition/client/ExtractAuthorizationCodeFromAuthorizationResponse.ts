import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExtractAuthorizationCodeFromAuthorizationResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const code = env.getString("authorization_endpoint_response", "code");

		if (!code) {
			throw this.error(
				"Couldn't find authorization code in authorization_endpoint_response, 'code' parameter is missing/empty",
			);
		} else {
			env.putString("code", code);

			this.logSuccess("Found authorization code", args("code", code));

			return env;
		}
	}
}
