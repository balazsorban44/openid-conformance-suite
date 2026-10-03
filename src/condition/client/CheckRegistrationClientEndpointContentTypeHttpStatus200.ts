import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export class CheckRegistrationClientEndpointContentTypeHttpStatus200 extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		const httpStatus = env.getInteger("registration_client_endpoint_response", "status");

		const expectedStatus = 200; // HttpStatus.OK

		if (httpStatus == null) {
			throw this.error("Http status can not be null.");
		}

		const expectedValue = expectedStatus;

		if (httpStatus !== expectedValue) {
			throw this.error("Invalid http status", args("actual", httpStatus, "expected", expectedValue));
		}

		this.logSuccess("registration_client_endpoint_response http status code was " + expectedValue);

		return env;
	}
}
