import { AbstractCondition, args, type Environment, type JsonObject } from "../../../framework/index.ts";

//We were ignoring what the client requested and overriding it with the expected method but
// as discussed on slack on 2020-07-02, we will deny registration
// if the requested method is set and different from the expected method
// Still allows registration if token_endpoint_auth_method is not set
export abstract class AbstractEnsureTokenEndPointAuthMethod extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		const expectedMethod = this.expectedTokenEndPointAuthMethod();
		const client = env.getObject("client") as JsonObject;
		if (!("token_endpoint_auth_method" in client)) {
			this.log(
				"token_endpoint_auth_method is not set, client will be registered using '" +
					expectedMethod +
					"' as required by this test",
			);
			return env;
		}

		const method = env.getString("client", "token_endpoint_auth_method");
		if (expectedMethod === method) {
			this.logSuccess("token_endpoint_auth_method is '" + expectedMethod + "' as expected");
			return env;
		}

		throw this.error(
			"token_endpoint_auth_method is set to '" + method + "' but this test requires '" + expectedMethod + "'",
			args("expected", expectedMethod, "actual", method),
		);
	}

	protected abstract expectedTokenEndPointAuthMethod(): string;
}
