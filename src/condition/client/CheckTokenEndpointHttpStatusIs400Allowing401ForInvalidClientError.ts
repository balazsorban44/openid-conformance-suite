import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const httpStatus = env.getInteger("token_endpoint_response_http_status");

		if (httpStatus == null) {
			throw this.error("Http status can not be null.");
		}

		const error = env.getString("token_endpoint_response", "error");

		if (!error) {
			throw this.error("Couldn't find error field");
		}

		// HttpStatus.SC_BAD_REQUEST = 400, HttpStatus.SC_UNAUTHORIZED = 401
		if (error === "invalid_client") {
			if (httpStatus !== 400 && httpStatus !== 401) {
				throw this.error(
					"Invalid http status for error invalid_client",
					args("actual", httpStatus, "expected", "400 or 401"),
				);
			}
		} else {
			if (httpStatus !== 400) {
				throw this.error(
					"Http status must be 400 for token endpoint errors other than invalid_client",
					args("actual", httpStatus, "expected", 400),
				);
			}
		}

		this.logSuccess("Token endpoint http status code was " + httpStatus + " for error '" + error + "'");

		return env;
	}
}
