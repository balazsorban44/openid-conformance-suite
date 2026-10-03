import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureDiscoveryEndpointResponseStatusCodeIs200 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["discovery_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		// UPSTREAM: unboxes an Integer without a null check (a missing status throws a NullPointerException)
		const statusCode = env.getInteger("discovery_endpoint_response", "status") as number;

		if (statusCode !== 200) {
			throw this.error(
				"discovery_endpoint_response returned an unexpected status code",
				args("http_status", statusCode),
			);
		}

		this.logSuccess("discovery_endpoint_response returned http 200 as expected", args("http_status", statusCode));

		return env;
	}
}
