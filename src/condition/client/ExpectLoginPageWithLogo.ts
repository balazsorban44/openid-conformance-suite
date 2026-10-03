import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectLoginPageWithLogo extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["login_page_placeholder"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"The login page should show the OpenID logo (as displayed on this server) - upload a screenshot of the login page.",
		);
		env.putString("login_page_placeholder", placeholder);
		return env;
	}
}
