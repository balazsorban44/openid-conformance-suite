import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class EnsureClientHasBackChannelLogoutUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const uri = env.getString("client", "backchannel_logout_uri");

		if (uri == null || uri === "") {
			throw this.error("backchannel_logout_uri is not defined for the client");
		}

		this.logSuccess("backchannel_logout_uri is set", args("backchannel_logout_uri", uri));

		return env;
	}
}
