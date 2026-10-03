import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreateTosUri extends AbstractCondition {
	private static readonly TOS_URI = "https://openid.net";

	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["tos_uri"] };

	override evaluate(env: Environment): Environment {
		env.putString("tos_uri", CreateTosUri.TOS_URI);

		this.log("Generated TOS URI", args("tos_uri", CreateTosUri.TOS_URI));

		return env;
	}
}
