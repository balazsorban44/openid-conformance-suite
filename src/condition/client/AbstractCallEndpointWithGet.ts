import { HttpClientException, type Environment, type JsonObject } from "../../framework/index.ts";
import { AbstractCallEndpoint, checkResponseForError, type ResponseErrorHandler } from "./AbstractCallEndpoint.ts";

/**
 * General utility class for calling endpoints and returning the full response
 */
export abstract class AbstractCallEndpointWithGet extends AbstractCallEndpoint {
	/**
	 * @param acceptHeader the media types for the Accept header (Java: List<MediaType>), e.g. ["application/json"]
	 */
	protected async callEndpointWithGet(
		env: Environment,
		errorHandler: ResponseErrorHandler | null,
		acceptHeader: string[],
		endpointUri: string,
		endpointName: string,
		responseEnvironmentKey: string,
	): Promise<Environment> {
		this.endpointName = endpointUri; // UPSTREAM: the endpointName parameter is only used in the success message
		this.responseEnvironmentKey = responseEnvironmentKey;

		const client = this.createHttpClient(env);
		try {
			const headers = new Headers();
			headers.set("accept", acceptHeader.join(", "));

			try {
				const response = await client.exchange({ url: endpointUri, method: "GET", headers });
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
