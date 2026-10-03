import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType extends AbstractCondition {
	private static readonly EXPECTED_VALUES: string[] = ["unsupported_response_type", "invalid_request"];

	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const error = env.getString("authorization_endpoint_response", "error");
		const EXPECTED_VALUES =
			CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType.EXPECTED_VALUES;

		if (!error) {
			throw this.error("Expected 'error' field not found");
		} else if (!EXPECTED_VALUES.includes(error)) {
			throw this.error("'error' field has unexpected value", args("expected", EXPECTED_VALUES, "actual", error));
		} else {
			this.logSuccess(
				"Authorization endpoint returned expected error",
				args("expected", EXPECTED_VALUES, "actual", error),
			);
			return env;
		}
	}
}
