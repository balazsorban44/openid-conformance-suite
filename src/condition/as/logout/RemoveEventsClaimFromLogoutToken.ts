import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class RemoveEventsClaimFromLogoutToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["logout_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["logout_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("logout_token_claims") as JsonObject;

		delete claims["events"];

		env.putObject("logout_token_claims", claims);

		this.log("Removed events from logout token claims", args("logout_token_claims", claims));

		return env;
	}
}
