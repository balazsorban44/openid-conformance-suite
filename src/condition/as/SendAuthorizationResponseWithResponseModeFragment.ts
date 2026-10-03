import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateAuthorizationEndpointResponseParams } from "./CreateAuthorizationEndpointResponseParams.ts";

// Port of the part of org.springframework.web.util.UriComponentsBuilder that is used here:
// toUriString() encodes every query parameter name and value as a URI query parameter component, i.e. everything
// except unreserved characters, sub-delimiters (other than '&' and '='), ':', '@', '/' and '?' is percent-encoded
// (UTF-8). In particular a space becomes %20 and a literal '+' is left alone.
function isQueryParamChar(c: string): boolean {
	return /^[A-Za-z0-9\-._~!$'()*+,;:@/?]$/.test(c);
}

function encodeQueryParamComponent(source: string): string {
	let out = "";
	for (const c of source) {
		if (isQueryParamChar(c)) {
			out += c;
		} else {
			for (const b of Buffer.from(c, "utf8")) {
				out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
			}
		}
	}
	return out;
}

export class SendAuthorizationResponseWithResponseModeFragment extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: [CreateAuthorizationEndpointResponseParams.ENV_KEY] };
	static override post: EnvironmentRequirements = { strings: ["authorization_endpoint_response_redirect"] };

	override evaluate(env: Environment): Environment {
		const params = env.getObject(CreateAuthorizationEndpointResponseParams.ENV_KEY) as JsonObject;

		const redirectUri = OIDFJSON.getString(params["redirect_uri"]);
		delete params["redirect_uri"];

		// UriComponentsBuilder.newInstance() with only query parameters; toUriString() gives "?name=value&name2=value2"
		const queryParams: string[] = [];
		for (const paramName of Object.keys(params)) {
			queryParams.push(
				encodeQueryParamComponent(paramName) + "=" + encodeQueryParamComponent(OIDFJSON.getString(params[paramName])),
			);
		}
		let paramsAsString = queryParams.length > 0 ? "?" + queryParams.join("&") : "";

		if (paramsAsString.startsWith("?")) {
			paramsAsString = paramsAsString.substring(1);
		}

		const redirectTo = redirectUri + "#" + paramsAsString;

		this.log("Redirecting back to client", args("uri", redirectTo));

		env.putString("authorization_endpoint_response_redirect", redirectTo);

		return env;
	}
}
