import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SignIdTokenWithAlgNone extends AbstractCondition {
	private static readonly ALG_NONE_HEADER = Buffer.from('{"alg":"none"}', "utf8").toString("base64url");

	static override pre: EnvironmentRequirements = { required: ["id_token_claims"] };
	static override post: EnvironmentRequirements = { strings: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("id_token_claims") as JsonObject;
		const jwt =
			SignIdTokenWithAlgNone.ALG_NONE_HEADER +
			"." +
			Buffer.from(JSON.stringify(claims), "utf8").toString("base64url") +
			".";
		this.logSuccess("Created id_token with alg none", args("id_token", jwt));
		env.putString("id_token", jwt);
		return env;
	}
}
