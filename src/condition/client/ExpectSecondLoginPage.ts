import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectSecondLoginPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["expect_second_login_page"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"The server must ask the user to login for a second time; a screenshot of this must be uploaded.",
		);
		env.putString("expect_second_login_page", placeholder);
		return env;
	}
}
