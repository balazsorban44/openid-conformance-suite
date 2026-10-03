import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectResponseTypeMissingErrorPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["response_type_missing_error"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"Upload a screenshot of the error page showing a missing response type error.",
		);
		env.putString("response_type_missing_error", placeholder);

		return env;
	}
}
