import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
	type JsonArray,
} from "../../framework/index.ts";

export class AddPostLogoutRedirectUriToDynamicRegistrationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dynamic_registration_request"],
		strings: ["post_logout_redirect_uri"],
	};
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_request"] };

	override evaluate(env: Environment): Environment {
		const postLogoutRedirectUri = env.getString("post_logout_redirect_uri") as string;

		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;

		const uris: JsonArray = [];
		uris.push(postLogoutRedirectUri);

		dynamicRegistrationRequest["post_logout_redirect_uris"] = uris;

		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log(
			"Added post_logout_redirect_uris to dynamic registration request",
			args("dynamic_registration_request", dynamicRegistrationRequest),
		);

		return env;
	}
}
