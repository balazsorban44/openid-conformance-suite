import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckStateInAuthorizationResponse extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const actual = env.getString("authorization_endpoint_response", "state");
		const expected = env.getString("state");

		if (!expected) {
			// we didn't save a 'state' value, we need to make sure one wasn't returned
			if (!actual) {
				// we're good
				this.logSuccess("No state in response to check");
				return env;
			} else {
				throw this.error(
					"No state value was sent, but a state in response was returned",
					args("expected", expected ?? "", "actual", actual ?? ""),
				);
			}
		} else {
			const error = env.getString("authorization_endpoint_response", "error");

			// we did save a state parameter, make sure it's the same as before
			if (expected === actual) {
				// we're good
				this.logSuccess("State in response correctly returned", args("state", actual));

				return env;
			} else if (!actual && !!error && error === "invalid_request_object") {
				this.logSuccess(
					"State is missing from response; this is permitted when the returned error is 'invalid_request_object' and the state was contained in the request object",
				);

				return env;
			} else if (!actual && !!error && error === "invalid_request_uri") {
				this.logSuccess(
					"State is missing from response; this is permitted when the returned error is 'invalid_request_uri' and the state was contained in the par request",
				);

				return env;
			} else if (!actual) {
				throw this.error(
					"State was passed in request, but is missing from response (or returned in the wrong place)",
					args("expected", expected ?? "", "actual", actual ?? ""),
				);
			} else {
				throw this.error("State in response did not match", args("expected", expected ?? "", "actual", actual ?? ""));
			}
		}
	}
}
