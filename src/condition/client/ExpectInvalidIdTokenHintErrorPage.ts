import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExpectInvalidIdTokenHintErrorPage extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["invalid_id_token_hint_error"] };

	override evaluate(env: Environment): Environment {
		const placeholder = this.createBrowserInteractionPlaceholder(
			"The server must show an error page saying the request is invalid as the id_token_hint is not valid - upload a screenshot of the error page.",
		);
		env.putString("invalid_id_token_hint_error", placeholder);
		return env;
	}
}
