import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectIdTokenHintRequiredErrorPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["id_token_hint_required_error"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"The server must show an error page saying the request is invalid as the id_token_hint is missing - upload a screenshot of the error page.",
		);
		env.putString("id_token_hint_required_error", placeholder);
		return env;
	}
}
