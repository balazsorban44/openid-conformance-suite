import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectPostLogoutRedirectUriNotRegisteredErrorPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["post_logout_redirect_uri_not_registered_error"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"The server must show an error page saying the request is invalid as the post_logout_redirect_uri is not a registered one - upload a screenshot of the error page.",
		);
		env.putString("post_logout_redirect_uri_not_registered_error", placeholder);
		return env;
	}
}
