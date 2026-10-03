import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectRedirectUriMissingErrorPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["redirect_uri_missing_error"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"Show an error page saying the redirect uri is missing from the request.",
		);
		env.putString("redirect_uri_missing_error", placeholder);
		return env;
	}
}
