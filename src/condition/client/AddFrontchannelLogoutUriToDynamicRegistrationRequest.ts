import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddFrontchannelLogoutUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dynamic_registration_request"],
		strings: ["frontchannel_logout_uri"],
	};
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const frontchannelLogoutUri = env.getString("frontchannel_logout_uri") as string;

		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		dynamicRegistrationRequest["frontchannel_logout_uri"] = frontchannelLogoutUri;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added frontchannel_logout_uri to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}
