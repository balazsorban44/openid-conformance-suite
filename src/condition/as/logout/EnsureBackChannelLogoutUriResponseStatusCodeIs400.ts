import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class EnsureBackChannelLogoutUriResponseStatusCodeIs400 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["backchannel_logout_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const statusCode = env.getInteger("backchannel_logout_endpoint_response", "status") as number;

		if (statusCode !== 400) {
			throw this.error("backchannel_logout_uri returned an unexpected response", args("http_status", statusCode));
		}

		this.logSuccess("backchannel_logout_uri returned http 400 as expected", args("http_status", statusCode));

		return env;
	}
}
