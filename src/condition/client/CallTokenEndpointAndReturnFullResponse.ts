import {
	mapToJsonObject,
	type Environment,
	type EnvironmentRequirements,
	type HttpResponse,
	type JsonObject,
} from "../../framework/index.ts";
import { IGNORE_ALL_ERRORS_HANDLER, type ResponseErrorHandler } from "./AbstractCallEndpoint.ts";
import { AbstractCallOAuthEndpoint } from "./AbstractCallOAuthEndpoint.ts";

export class CallTokenEndpointAndReturnFullResponse extends AbstractCallOAuthEndpoint {
	static override pre: EnvironmentRequirements = {
		required: ["server", "token_endpoint_request_form_parameters"],
	};
	static override post: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override async evaluate(env: Environment): Promise<Environment> {
		// Treat all http status codes as 'not an error', so spring never throws an exception due to the http
		// status code meaning the rest of our code can handle http status codes how it likes
		return await this.callTokenEndpoint(env, IGNORE_ALL_ERRORS_HANDLER);
	}

	async callTokenEndpoint(env: Environment, errorHandler: ResponseErrorHandler | null): Promise<Environment> {
		// build up the form
		const requestFormParametersEnvKey = "token_endpoint_request_form_parameters";
		const requestHeadersEnvKey = "token_endpoint_request_headers";
		const tokenEndpointUri =
			env.getString("token_endpoint") != null
				? (env.getString("token_endpoint") as string)
				: (env.getString("server", "token_endpoint") as string);
		const endpointName = "token endpoint";
		const envResponseKey = "token_endpoint_response_full";

		return await this.callOAuthEndpoint(
			env,
			errorHandler,
			requestFormParametersEnvKey,
			requestHeadersEnvKey,
			tokenEndpointUri,
			endpointName,
			envResponseKey,
		);
	}

	protected override addFullResponse(env: Environment, response: HttpResponse): void {
		super.addFullResponse(env, response);

		// add some legacy values - ideally we would refactor all the conditions that use these to read from
		// token_endpoint_response_full instead.
		env.putInteger("token_endpoint_response_http_status", response.status);

		const responseHeaders = mapToJsonObject(response.headers, true);

		env.putObject("token_endpoint_response_headers", responseHeaders);

		const bodyJson = env.getElementFromObject("token_endpoint_response_full", "body_json");
		if (bodyJson != null) {
			env.putObject("token_endpoint_response", bodyJson as JsonObject);
		}
	}
}
