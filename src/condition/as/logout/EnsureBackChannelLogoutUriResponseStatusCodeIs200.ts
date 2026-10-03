import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class EnsureBackChannelLogoutUriResponseStatusCodeIs200 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["backchannel_logout_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const statusCode = env.getInteger("backchannel_logout_endpoint_response", "status") as number;

		if (statusCode !== 200) {
			throw this.error("backchannel_logout_uri returned an unexpected http status", args("http_status", statusCode));
		}

		this.logSuccess("backchannel_logout_uri returned the expected http status", args("http_status", statusCode));

		return env;
	}
}
