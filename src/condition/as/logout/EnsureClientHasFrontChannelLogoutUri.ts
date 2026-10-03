import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class EnsureClientHasFrontChannelLogoutUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const frontchannelLogoutUri = env.getString("client", "frontchannel_logout_uri");

		if (frontchannelLogoutUri == null || frontchannelLogoutUri === "") {
			throw this.error("frontchannel_logout_uri is not defined for the client");
		}

		this.logSuccess("frontchannel_logout_uri is set", args("frontchannel_logout_uri", frontchannelLogoutUri));

		return env;
	}
}
