import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectLoginPageWithPolicyLink extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["login_page_placeholder"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"The login page should show a link to a policy document - upload a screenshot of the login page.",
		);
		env.putString("login_page_placeholder", placeholder);
		return env;
	}
}
