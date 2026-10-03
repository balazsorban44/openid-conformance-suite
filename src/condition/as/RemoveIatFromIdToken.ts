import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class RemoveIatFromIdToken extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;

		delete claims["iat"];

		env.putObject("id_token_claims", claims);

		this.logSuccess("Removed iat from ID token claims", args("id_token_claims", claims));

		return env;
	}
}
