import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureBearerAccessTokenNotInParams extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["incoming_request"] };

	override evaluate(env: Environment): Environment {
		const incomingQuery = env.getString("incoming_request", "query_string_params.access_token");
		const incomingForm = env.getString("incoming_request", "body_form_params.access_token");

		if (incomingQuery) {
			throw this.error(
				"Client incorrectly supplied access token in query parameters",
				args("access_token", incomingQuery),
			);
		}
		if (incomingForm) {
			throw this.error(
				"Client incorrectly supplied access token in form parameters",
				args("access_token", incomingForm),
			);
		}
		this.logSuccess("Client correctly did not send access token in query parameters or form body");
		return env;
	}
}
