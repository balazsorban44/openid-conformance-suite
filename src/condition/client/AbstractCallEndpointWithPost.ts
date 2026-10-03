import {
	headersFromJson,
	HttpClientException,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractCallEndpoint, checkResponseForError, type ResponseErrorHandler } from "./AbstractCallEndpoint.ts";

/**
 * General utility class for calling endpoints and returning the full response
 */
export abstract class AbstractCallEndpointWithPost extends AbstractCallEndpoint {
	/**
	 * POST a JSON string body to the given endpoint. The response (status, headers, body)
	 * is stored in the environment under {@code responseEnvironmentKey}.
	 */
	protected async callEndpointWithJsonBody(
		env: Environment,
		jsonBody: string,
		endpointUri: string,
		endpointName: string,
		responseEnvironmentKey: string,
	): Promise<Environment> {
		this.endpointName = endpointName;
		this.responseEnvironmentKey = responseEnvironmentKey;

		const client = this.createHttpClient(env);
		try {
			const headers = new Headers();
			headers.set("content-type", "application/json");

			try {
				const response = await client.exchange({ url: endpointUri, method: "POST", headers, body: jsonBody });
				const responseException = checkResponseForError(null, response);
				if (responseException != null) {
					return this.handleRestClientResponseException(env, responseException);
				}
				this.addFullResponse(env, response);
			} catch (e) {
				if (e instanceof HttpClientException) {
					return this.handleClientException(env, e);
				}
				throw e;
			}

			this.logSuccess("Got " + endpointName + " response", env.getObject(responseEnvironmentKey) as JsonObject);
			return env;
		} finally {
			await client.close();
		}
	}

	protected async callEndpointWithPost(
		env: Environment,
		errorHandler: ResponseErrorHandler | null,
		requestFormParametersEnvKey: string | null,
		requestHeadersEnvKey: string | null,
		endpointUri: string,
		endpointName: string,
		responseEnvironmentKey: string,
	): Promise<Environment> {
		this.endpointName = endpointUri; // UPSTREAM: the endpointName parameter is only used in the success message
		this.responseEnvironmentKey = responseEnvironmentKey;

		let form: URLSearchParams | null = null;
		if (requestFormParametersEnvKey != null) {
			form = new URLSearchParams();
			const formJson = env.getObject(requestFormParametersEnvKey) as JsonObject;
			for (const key of Object.keys(formJson)) {
				const json = formJson[key];
				if (isJsonObject(json)) {
					form.append(key, JSON.stringify(json));
				} else {
					form.append(key, OIDFJSON.getString(formJson[key]));
				}
			}
		}

		const client = this.createHttpClient(env);
		try {
			const headers = headersFromJson(requestHeadersEnvKey != null ? env.getObject(requestHeadersEnvKey) : null);
			try {
				const response = await client.exchange({ url: endpointUri, method: "POST", headers, body: form });
				const responseException = checkResponseForError(errorHandler, response);
				if (responseException != null) {
					return this.handleRestClientResponseException(env, responseException);
				}
				this.addFullResponse(env, response);
			} catch (e) {
				if (e instanceof HttpClientException) {
					return this.handleClientException(env, e);
				}
				throw e;
			}

			this.logSuccess("Got " + endpointName + " response", env.getObject(responseEnvironmentKey) as JsonObject);
			return env;
		} finally {
			await client.close();
		}
	}
}
