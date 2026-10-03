import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectRedirectUriErrorPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["redirect_uri_error"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder("Show redirect URI error page");
		env.putString("redirect_uri_error", placeholder);

		return env;
	}
}
