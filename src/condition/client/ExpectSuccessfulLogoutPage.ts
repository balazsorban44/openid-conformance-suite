import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectSuccessfulLogoutPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["successful_logout_page"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"The server must log the user out - upload a screenshot of the successful logout page.",
		);
		env.putString("successful_logout_page", placeholder);
		return env;
	}
}
