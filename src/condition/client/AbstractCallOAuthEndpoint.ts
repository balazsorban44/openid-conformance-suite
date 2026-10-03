import {
	headersFromJson,
	HttpClientException,
	isJsonObject,
	OIDFJSON,
	args,
	type Environment,
	type HttpResponse,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractCallEndpoint, checkResponseForError, type ResponseErrorHandler } from "./AbstractCallEndpoint.ts";

/**
 * General utility class for calling OAuth endpoints
 *
 * This is defined as an endpoint with similar behaviour to the token endpoint, which is the case for most
 * OAuth endpoints that need client authentication - they make a POST request with form encoded contents
 * and expect a JSON response.
 */
export abstract class AbstractCallOAuthEndpoint extends AbstractCallEndpoint {
	protected async callOAuthEndpoint(
		env: Environment,
		errorHandler: ResponseErrorHandler | null,
		requestFormParametersEnvKey: string,
		requestHeadersEnvKey: string | null,
		endpointUri: string,
		endpointName: string,
		responseEnvironmentKey: string,
	): Promise<Environment> {
		this.endpointName = endpointUri; // UPSTREAM: the field is set to the URI (used by the handle*Exception methods); the endpointName parameter is used in the messages below
		this.responseEnvironmentKey = responseEnvironmentKey;

		const formJson = env.getObject(requestFormParametersEnvKey) as JsonObject;
		const form = new URLSearchParams();
		for (const key of Object.keys(formJson)) {
			const json = formJson[key];
			if (isJsonObject(json)) {
				// presentation submission etc are objects
				form.append(key, JSON.stringify(json));
			} else {
				form.append(key, OIDFJSON.getString(formJson[key]));
			}
		}

		const client = this.createHttpClient(env);
		try {
			const headers = headersFromJson(requestHeadersEnvKey != null ? env.getObject(requestHeadersEnvKey) : null);

			headers.set("accept", "application/json");

			let jsonString: string | null = null;

			try {
				const response: HttpResponse = await client.exchange({
					url: endpointUri,
					method: "POST",
					headers,
					body: form,
				});
				const responseException = checkResponseForError(errorHandler, response);
				if (responseException != null) {
					return this.handleRestClientResponseException(env, responseException);
				}

				jsonString = response.body;
				this.addFullResponse(env, response);
			} catch (e) {
				if (e instanceof HttpClientException) {
					return this.handleClientException(env, e);
				}
				throw e;
			}

			if (jsonString == null || jsonString === "") {
				throw this.error("Missing or empty response from the " + endpointName);
			}

			if (this.jsonParseError && this.jsonParseException != null) {
				return this.handleJsonParseException(env, this.jsonParseException);
			}
			if (this.jsonObjectError) {
				throw this.error(endpointName + " did not return a JSON object", args("response", jsonString));
			}
			this.logSuccess(
				"Parsed " + endpointName + " response" + this.parsedResponseLogSuffix(),
				env.getObject(responseEnvironmentKey) as JsonObject,
			);
			return env;
		} finally {
			await client.close();
		}
	}

	/**
	 * Appended to the message of the "Parsed ... response" entry. Subclasses override this to say, in the
	 * part of the entry visible without expanding it, what the server did on this particular response -
	 * putting it here rather than in an entry of its own keeps the number of entries one call produces the
	 * same whatever the server sent, which the CI compare-results job depends on.
	 */
	protected parsedResponseLogSuffix(): string {
		return "";
	}
}
