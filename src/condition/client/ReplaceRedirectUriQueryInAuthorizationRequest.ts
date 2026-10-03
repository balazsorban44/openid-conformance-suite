import {
	AbstractCondition,
	args,
	has,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ReplaceRedirectUriQueryInAuthorizationRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["redirect_uri"] };

	override evaluate(env: Environment): Environment {
		const request = env.getObject("authorization_endpoint_request") as JsonObject;

		if (!has(request, "redirect_uri")) {
			throw this.error("redirect_uri was not found in authorization_endpoint_request");
		}

		const redirectUri = OIDFJSON.getString(request["redirect_uri"]);

		// UPSTREAM: Spring's DefaultUriBuilderFactory does not normalise the URI; WHATWG URL does (e.g. an empty
		// path of an http(s) URL becomes "/"), so the resulting string can differ slightly for such redirect URIs.
		const url = new URL(redirectUri);
		url.search = "";
		url.searchParams.append("foo", "bar");
		const redirectUriWithQuery = url.toString();

		delete request["redirect_uri"];
		request["redirect_uri"] = redirectUriWithQuery;

		this.log("Updated redirect_uri in authorization endpoint request", args("redirect_uri", redirectUriWithQuery));

		return env;
	}
}
