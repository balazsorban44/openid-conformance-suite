import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export abstract class AbstractEnsureHttpStatusCode extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const statusCode = env.getInteger("endpoint_response", "status") as number;
		const endpointName = env.getString("endpoint_response", "endpoint_name");

		if (statusCode !== this.getExpectedStatusCode()) {
			throw this.error(
				endpointName + " endpoint returned an unexpected http status",
				args("http_status", statusCode, "expected_status", this.getExpectedStatusCode()),
			);
		}

		this.logSuccess(
			endpointName + " endpoint returned the expected http status",
			args("http_status", statusCode, "expected_status", this.getExpectedStatusCode()),
		);

		return env;
	}

	protected abstract getExpectedStatusCode(): number;
}
