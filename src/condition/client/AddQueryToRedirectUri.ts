import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class AddQueryToRedirectUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["redirect_uri"] };

	override evaluate(env: Environment): Environment {
		const redirectUri = env.getString("redirect_uri") as string;

		const url = new URL(redirectUri);
		url.searchParams.append("bar", "foo");
		const redirectUriWithQuery = url.toString();

		env.putString("redirect_uri", redirectUriWithQuery);

		this.log("Updated redirect_uri", args("redirect_uri", redirectUriWithQuery));

		return env;
	}
}
