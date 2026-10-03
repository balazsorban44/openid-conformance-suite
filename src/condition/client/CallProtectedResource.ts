import {
	headersFromJson,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractCallProtectedResourceWithBearerToken } from "./AbstractCallProtectedResourceWithBearerToken.ts";

/**
 * This is to call a generic resource server endpoint with an access token.
 *
 * Note that this returns success if the HTTP transaction returns a valid response
 * (i.e. no network error occurred) - regardless of the http status - callers will
 * generally need to explicitly verify the http status.
 */
export class CallProtectedResource extends AbstractCallProtectedResourceWithBearerToken {
	static override pre: EnvironmentRequirements = {
		required: ["access_token"],
		strings: ["protected_resource_url"],
	};
	static override post: EnvironmentRequirements = { required: ["resource_endpoint_response_full"] };

	protected override treatAllHttpStatusAsSuccess(): boolean {
		// Treat all http status codes as 'not an error', so spring never throws an exception due to the http
		// status code meaning the rest of our code can handle http status codes how it likes
		return true;
	}

	override async evaluate(env: Environment): Promise<Environment> {
		return await this.callProtectedResource(env);
	}

	protected override getHeaders(env: Environment): Headers {
		let headers = super.getHeaders(env);

		const requestHeaders = env.getObject("resource_endpoint_request_headers");

		headers = headersFromJson(requestHeaders, headers);

		return headers;
	}

	protected override handleClientResponse(
		env: Environment,
		_responseCode: JsonObject,
		responseBody: string | null,
		responseHeaders: JsonObject,
		fullResponse: JsonObject,
	): Environment {
		env.putObject("resource_endpoint_response_full", fullResponse);

		// Temporarily store to "old" environment locations; these are deprecated and we
		// should change conditions to use resource_endpoint_response_full to avoid
		// having the same information stored in different places.
		env.putString("resource_endpoint_response", responseBody);
		env.putObject("resource_endpoint_response_headers", responseHeaders);

		// Once we've done the above, we should make this condition explicitly remove
		// the old locations, as other conditions may still be writing to them and we
		// don't want to accidentally use data from other responses:
		//		env.removeNativeValue("resource_endpoint_response");
		//		env.removeObject("resource_endpoint_response_headers");

		this.logSuccess("Got a response from the resource endpoint", fullResponse);
		return env;
	}
}
