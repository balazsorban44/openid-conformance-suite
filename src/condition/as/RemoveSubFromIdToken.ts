import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class RemoveSubFromIdToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		delete claims["sub"];

		env.putObject("id_token_claims", claims);

		this.log("Removed sub value from ID token claims", args("id_token_claims", claims));

		return env;
	}
}
