import {
	AbstractCondition,
	headersFromJson,
	HttpClientException,
	isJsonArray,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type HttpRequest,
	type HttpResponse,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * This class makes a http post to PAR endpoint and the response is stored in the ENV
 */
export class CallPAREndpoint extends AbstractCondition {
	static readonly HTTP_METHOD_KEY = "par_endpoint_http_method";
	static readonly RESPONSE_KEY = "pushed_authorization_endpoint_response";
	static readonly RESPONSE_HEADERS_KEY = "pushed_authorization_endpoint_response_headers";

	static override pre: EnvironmentRequirements = {
		required: ["server", "pushed_authorization_request_form_parameters"],
	};
	static override post: EnvironmentRequirements = { required: [CallPAREndpoint.RESPONSE_KEY] };

	override async evaluate(env: Environment): Promise<Environment> {
		// Java passes a DefaultResponseErrorHandler whose hasError() always returns false: all http status codes are
		// treated as 'not an error', which is also how HttpClient behaves (no status ever throws)
		return await this.callParEndpoint(env);
	}

	protected async callParEndpoint(env: Environment): Promise<Environment> {
		// build up the form
		const formJson = env.getObject("pushed_authorization_request_form_parameters") as JsonObject;
		const form = new URLSearchParams();
		for (const key of Object.keys(formJson)) {
			const el = formJson[key];
			if (isJsonObject(el)) {
				// e.g. claims parameter
				form.append(key, JSON.stringify(el));
			} else if (isJsonArray(el)) {
				form.append(key, JSON.stringify(el));
			} else {
				form.append(key, OIDFJSON.getString(el));
			}
		}

		const client = this.createHttpClient(env);
		try {
			const headers = headersFromJson(env.getObject("pushed_authorization_request_endpoint_request_headers"));
			headers.set("accept", "application/json");
			headers.set("content-type", "application/x-www-form-urlencoded");

			const httpMethod: string =
				env.getString(CallPAREndpoint.HTTP_METHOD_KEY) == null
					? "POST"
					: (env.getString(CallPAREndpoint.HTTP_METHOD_KEY) as string);

			try {
				let parEndpointUri: string | null = null;
				if (env.containsObject("mutual_tls_authentication")) {
					// the MTLS aliased endpoint if we have MTLS authentication available.
					// This is to cater for private_key_jwt (where we should not use the alias) and mtls client auth
					// (where we should); it assumes the caller only supplies mutual_tls_authentication for the calls
					// it is required for.
					// I think here we could just call env.getString("server", "mtls_endpoint_aliases.pushed_authorization_request_endpoint");
					// but https://gitlab.com/openid/conformance-suite/-/issues/914 is open to reconsider the overall
					// mechanism.
					parEndpointUri = env.getString("pushed_authorization_request_endpoint");
				}

				if (parEndpointUri == null) {
					parEndpointUri = env.getString("server", "pushed_authorization_request_endpoint");
				}
				if (!parEndpointUri) {
					throw this.error(
						"Couldn't find pushed_authorization_request_endpoint in server discovery document. This endpoint is required as you have selected to test pushed authorization requests.",
					);
				}

				const response = await client.exchange({
					url: parEndpointUri,
					method: httpMethod as HttpRequest["method"],
					headers,
					body: form,
				});

				this.addFullResponse(env, response);
			} catch (e) {
				if (e instanceof HttpClientException) {
					return this.handleClientException(env, e);
				}
				throw e;
			}

			if (httpMethod !== "POST") {
				// allow non-JSON responses when trying GET (which must be rejected)
				return env;
			}

			const jsonRoot = env.getElementFromObject(CallPAREndpoint.RESPONSE_KEY, "body_json");
			if (jsonRoot == null || !isJsonObject(jsonRoot)) {
				throw this.error("Pushed Authorization did not return a JSON object");
			}

			this.logSuccess(
				"Parsed pushed authorization request endpoint response" + this.parsedResponseLogSuffix(),
				jsonRoot,
			);

			return env;
		} finally {
			await client.close();
		}
	}

	/** @see AbstractCallOAuthEndpoint#parsedResponseLogSuffix() */
	protected parsedResponseLogSuffix(): string {
		return "";
	}

	protected addFullResponse(env: Environment, response: HttpResponse): void {
		const fullResponse = this.convertJsonResponseForEnvironment("pushed authorization request", response, true);
		env.putObject(CallPAREndpoint.RESPONSE_KEY, fullResponse);

		env.putObject(CallPAREndpoint.RESPONSE_HEADERS_KEY, fullResponse["headers"] as JsonObject);
	}

	// Java's handleRestClientResponseException(env, RestClientResponseException) is never reached: the error handler
	// installed in evaluate() reports no HTTP status as an error, and HttpClient never throws on a status.

	protected handleClientException(_env: Environment, e: HttpClientException): Environment {
		let msg = "Call to pushed authorization request endpoint failed";
		if (e.cause != null) {
			msg += " - " + (e.cause instanceof Error ? e.cause.message : String(e.cause));
		}
		throw this.error(msg, e);
	}
}
