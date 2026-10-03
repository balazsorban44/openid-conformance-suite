import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class AddFragmentToRedirectUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["redirect_uri"] };

	override evaluate(env: Environment): Environment {
		const redirectUri = env.getString("redirect_uri") as string;

		const url = new URL(redirectUri);
		url.hash = "foobar";
		const redirectUriWithFragment = url.toString();

		env.putString("redirect_uri", redirectUriWithFragment);

		this.log("Updated redirect_uri", args("redirect_uri", redirectUriWithFragment));

		return env;
	}
}
