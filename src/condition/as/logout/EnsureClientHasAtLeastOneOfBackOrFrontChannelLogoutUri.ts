import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class EnsureClientHasAtLeastOneOfBackOrFrontChannelLogoutUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const backChannelLogoutUri = env.getString("client", "backchannel_logout_uri");
		const frontChannelLogoutUri = env.getString("client", "frontchannel_logout_uri");

		let hasBackChannel = false;
		let hasFrontChannel = false;

		if (frontChannelLogoutUri != null && frontChannelLogoutUri !== "") {
			hasFrontChannel = true;
		}

		if (backChannelLogoutUri != null && backChannelLogoutUri !== "") {
			hasBackChannel = true;
		}
		if (hasBackChannel || hasFrontChannel) {
			this.logSuccess(
				"Client has either backchannel_logout_uri or frontchannel_logout_uri (or both) set",
				args("backchannel_logout_uri", backChannelLogoutUri, "frontchannel_logout_uri", frontChannelLogoutUri),
			);
		} else {
			throw this.error("At least one of backchannel_logout_uri or frontchannel_logout_uri is required");
		}

		return env;
	}
}
