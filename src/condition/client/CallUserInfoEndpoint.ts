import {
	args,
	headersFromJson,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractCallProtectedResourceWithBearerToken } from "./AbstractCallProtectedResourceWithBearerToken.ts";

export class CallUserInfoEndpoint extends AbstractCallProtectedResourceWithBearerToken {
	static override pre: EnvironmentRequirements = { required: ["access_token", "server"] };
	static override post: EnvironmentRequirements = { required: ["userinfo_endpoint_response_full"] };

	protected override treatAllHttpStatusAsSuccess(): boolean {
		// Treat all http status codes as 'not an error', so spring never throws an exception due to the http
		// status code meaning the rest of our code can handle http status codes how it likes
		return true;
	}

	protected override getHeaders(env: Environment): Headers {
		let headers = super.getHeaders(env);

		const requestHeaders = env.getObject("resource_endpoint_request_headers");

		headers = headersFromJson(requestHeaders, headers);

		return headers;
	}

	override async evaluate(env: Environment): Promise<Environment> {
		return await this.callProtectedResource(env);
	}

	protected override getUri(env: Environment): string {
		let resourceUri: string | null = null;

		if (env.containsObject("mutual_tls_authentication")) {
			resourceUri = env.getString("server", "mtls_endpoint_aliases.userinfo_endpoint");
		}
		if (resourceUri == null) {
			resourceUri = env.getString("server", "userinfo_endpoint");
		}
		if (!resourceUri) {
			throw this.error('"userinfo_endpoint" missing from server configuration');
		}

		return resourceUri;
	}

	protected override handleClientResponse(
		env: Environment,
		responseCode: JsonObject,
		responseBody: string | null,
		responseHeaders: JsonObject,
		fullResponse: JsonObject,
	): Environment {
		env.putObject("userinfo_endpoint_response_full", fullResponse);

		this.logSuccess(
			"Got a response from the userinfo endpoint",
			args("body", responseBody, "headers", responseHeaders, "status_code", responseCode),
		);
		return env;
	}
}
