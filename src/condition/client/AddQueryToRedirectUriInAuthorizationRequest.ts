import {
	AbstractCondition,
	OIDFJSON,
	args,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddQueryToRedirectUriInAuthorizationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const request = env.getObject("authorization_endpoint_request") as JsonObject;

		if (!has(request, "redirect_uri")) {
			throw this.error("redirect_uri was not found in authorization_endpoint_request");
		}

		const redirectUri = OIDFJSON.getString(request["redirect_uri"]);

		const url = new URL(redirectUri);
		url.searchParams.append("foo", "bar");
		const redirectUriWithQuery = url.toString();

		delete request["redirect_uri"];
		request["redirect_uri"] = redirectUriWithQuery;

		this.log("Updated redirect_uri in authorization endpoint request", args("redirect_uri", redirectUriWithQuery));

		return env;
	}
}
