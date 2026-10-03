import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class ValidateIdTokenHintInRPInitiatedLogoutRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["end_session_endpoint_http_request_params", "all_issued_id_tokens"],
	};

	override evaluate(env: Environment): Environment {
		const idTokenHint = env.getString("end_session_endpoint_http_request_params", "id_token_hint") as string;
		const issuedIdTokens = env.getObject("all_issued_id_tokens") as JsonObject;
		if (!(idTokenHint in issuedIdTokens)) {
			throw this.error(
				"Invalid id_token_hint, not an id_token issued by this test instance.",
				args("id_token_hint", idTokenHint, "issued_id_tokens", Object.keys(issuedIdTokens)),
			);
		}
		this.logSuccess("id_token_hint was issued by this test instance", args("id_token_hint", idTokenHint));
		return env;
	}
}
