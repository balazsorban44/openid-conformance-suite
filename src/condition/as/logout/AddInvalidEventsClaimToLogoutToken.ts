import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class AddInvalidEventsClaimToLogoutToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["logout_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["logout_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("logout_token_claims") as JsonObject;

		delete claims["events"];

		const events: JsonObject = {};
		events["http://schemas.openid.net/event/foobar"] = {};

		claims["events"] = events;

		env.putObject("logout_token_claims", claims);

		this.log("Added invalid events claim to logout token", args("logout_token_claims", claims));

		return env;
	}
}
