import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddCodeVerifierToTokenEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["token_endpoint_request_form_parameters"],
		strings: ["code_verifier"],
	};
	static override post: EnvironmentRequirements = { required: ["token_endpoint_request_form_parameters"] };

	override evaluate(env: Environment): Environment {
		const code_verifier = env.getString("code_verifier");
		if (!code_verifier) {
			throw this.error("Couldn't find code_verifier value");
		}

		const o = env.getObject("token_endpoint_request_form_parameters") as JsonObject;

		o["code_verifier"] = code_verifier;

		env.putObject("token_endpoint_request_form_parameters", o);

		this.log(o);

		return env;
	}
}
