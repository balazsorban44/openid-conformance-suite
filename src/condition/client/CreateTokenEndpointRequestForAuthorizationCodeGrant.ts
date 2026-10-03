import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateTokenEndpointRequestForAuthorizationCodeGrant extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["code", "redirect_uri"] };
	static override post: EnvironmentRequirements = { required: ["token_endpoint_request_form_parameters"] };

	override evaluate(env: Environment): Environment {
		const o: JsonObject = {};
		o["grant_type"] = "authorization_code";
		o["code"] = env.getString("code");
		o["redirect_uri"] = env.getString("redirect_uri");

		env.putObject("token_endpoint_request_form_parameters", o);

		// Reset headers so that we're truly starting a 'new' request
		env.putObject("token_endpoint_request_headers", {});

		this.logSuccess("Created token endpoint request", o);

		return env;
	}
}
