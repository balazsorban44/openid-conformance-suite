import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export class EnsureHttpStatusCodeIs4xx extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		const httpStatus = env.getInteger("endpoint_response", "status");
		const endpointName = env.getString("endpoint_response", "endpoint_name");

		if (httpStatus == null) {
			throw this.error("Http status can not be null.");
		}

		if (httpStatus >= 400 && httpStatus <= 499) {
			this.logSuccess(endpointName + " endpoint http status code was " + httpStatus);
			return env;
		}

		throw this.error(
			endpointName + " endpoint returned a different http status than expected",
			args("actual", httpStatus, "expected", "400 to 499"),
		);
	}
}
