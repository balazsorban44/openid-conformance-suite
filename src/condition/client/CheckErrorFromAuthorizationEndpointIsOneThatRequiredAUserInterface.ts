import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface extends AbstractCondition {
	// as per https://openid.net/specs/openid-connect-core-1_0.html#AuthError
	// matches https://github.com/rohe/oidctest/blob/master/test_tool/cp/test_op/flows/OP-prompt-none-NotLoggedIn.json#L38
	private static readonly EXPECTED_VALUES: string[] = [
		"interaction_required",
		"login_required",
		"account_selection_required",
		"consent_required",
	];

	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const error = env.getString("authorization_endpoint_response", "error");
		const EXPECTED_VALUES = CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface.EXPECTED_VALUES;

		if (!error) {
			throw this.error("Expected 'error' field not found");
		} else if (!EXPECTED_VALUES.includes(error)) {
			throw this.error("'error' field has an unexpected value", args("permitted", EXPECTED_VALUES, "actual", error));
		} else {
			this.logSuccess(
				"Authorization endpoint returned one of the permitted errors",
				args("permitted", EXPECTED_VALUES, "actual", error),
			);
			return env;
		}
	}
}
