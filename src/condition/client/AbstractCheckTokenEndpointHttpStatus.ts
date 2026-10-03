import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractCheckTokenEndpointHttpStatus extends AbstractCondition {
	/** @returns the expected status code (Java: HttpStatus, whose value() is the numeric code) */
	protected abstract getExpectedHttpStatus(): number;

	override evaluate(env: Environment): Environment {
		const httpStatus = env.getInteger("token_endpoint_response_http_status");

		const expectedStatus = this.getExpectedHttpStatus();

		if (httpStatus == null) {
			throw this.error("Http status can not be null.");
		}

		const expectedValue = expectedStatus;

		if (httpStatus !== expectedValue) {
			throw this.error("Invalid http status", args("actual", httpStatus, "expected", expectedValue));
		}

		this.logSuccess("Token endpoint http status code was " + expectedValue);

		return env;
	}
}
