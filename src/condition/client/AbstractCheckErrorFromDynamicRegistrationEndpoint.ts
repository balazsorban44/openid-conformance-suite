import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export abstract class AbstractCheckErrorFromDynamicRegistrationEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_endpoint_response"] };

	protected abstract getPermittedErrors(): string[];

	override evaluate(env: Environment): Environment {
		const error = env.getString("dynamic_registration_endpoint_response", "body_json.error");

		if (!error) {
			throw this.error("'error' field not found in response from dynamic registration endpoint");
		}

		const permittedErrors = this.getPermittedErrors();

		if (!permittedErrors.includes(error)) {
			throw this.error("'error' field has unexpected value", args("permitted", permittedErrors, "actual", error));
		}

		this.logSuccess(
			"Dynamic registration endpoint returned 'error'",
			args("permitted", permittedErrors, "error", error),
		);

		return env;
	}
}
