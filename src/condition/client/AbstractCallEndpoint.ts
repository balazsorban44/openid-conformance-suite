import {
	AbstractCondition,
	args,
	HttpClientException,
	JsonParseException,
	isJsonArray,
	isJsonObject,
	parseJson,
	type Environment,
	type HttpResponse,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Port of Spring's ResponseErrorHandler: decides whether a response is an error. When no handler is given the
 * Spring default applies (a 4xx or 5xx status is an error). HttpClient itself never treats a status as an error.
 */
export interface ResponseErrorHandler {
	hasError(response: HttpResponse): boolean;
}

/**
 * Equivalent of the anonymous DefaultResponseErrorHandler subclasses (and IgnoreErrorsErrorHandler) whose hasError
 * always returns false: all http status codes are 'not an error', so the calling code can handle http status codes
 * how it likes.
 */
export const IGNORE_ALL_ERRORS_HANDLER: ResponseErrorHandler = {
	hasError: () => false,
};

/** Port of Spring's RestClientResponseException: thrown for a response that the error handler reports as an error */
export class RestClientResponseException extends Error {
	readonly statusCode: number;
	readonly statusText: string;
	readonly responseBody: string;

	constructor(statusCode: number, statusText: string, responseBody: string) {
		super(statusCode + " " + statusText);
		this.name = "RestClientResponseException";
		this.statusCode = statusCode;
		this.statusText = statusText;
		this.responseBody = responseBody;
	}
}

/**
 * Spring's RestTemplate throws RestClientResponseException for responses its error handler reports as errors
 * (default: 4xx and 5xx). HttpClient never throws on a status, so callers use this to get the same behaviour.
 * @returns the exception Spring would have thrown, or null if the response is not an error
 */
export function checkResponseForError(
	errorHandler: ResponseErrorHandler | null | undefined,
	response: HttpResponse,
): RestClientResponseException | null {
	const hasError = errorHandler != null ? errorHandler.hasError(response) : response.status >= 400;
	if (!hasError) {
		return null;
	}
	return new RestClientResponseException(response.status, response.statusText, response.body ?? "");
}

/**
 * The message of the underlying I/O failure of a HttpClientException (Java: e.getCause().getMessage() of the
 * RestClientException), or null if there is none.
 */
export function causeMessageOf(e: HttpClientException): string | null {
	let cause: unknown = e.cause;
	if (cause == null) {
		return null;
	}
	if (cause instanceof Error && cause.cause instanceof Error) {
		// fetch wraps the real network error in a "fetch failed" TypeError
		cause = cause.cause;
	}
	return cause instanceof Error ? cause.message : String(cause);
}

/**
 * General utility class for calling endpoints.
 *
 * <p>New endpoint calls probably want one of the subclasses that provide ready-made HTTP helpers:
 * <ul>
 *   <li>{@link AbstractCallEndpointWithPost} — for POST requests</li>
 *   <li>{@link AbstractCallEndpointWithGet} — for GET requests</li>
 *   <li>{@link AbstractCallOAuthEndpoint} — for OAuth token endpoint calls</li>
 * </ul>
 */
export abstract class AbstractCallEndpoint extends AbstractCondition {
	protected jsonObjectError = false;
	protected jsonParseError = false;
	protected jsonParseException: JsonParseException | null = null;
	protected endpointName!: string;
	protected responseEnvironmentKey!: string;

	protected addFullResponse(env: Environment, response: HttpResponse): void {
		const fullResponse = this.convertJsonResponseForEnvironment(this.endpointName, response, true);
		env.putObject(this.responseEnvironmentKey, fullResponse);
	}

	protected override convertJsonResponseForEnvironment(
		endpointName: string,
		response: HttpResponse,
		allowParseFailure = false,
	): JsonObject {
		this.jsonParseError = false;
		this.jsonObjectError = false;
		this.jsonParseException = null;

		const responseInfo = this.convertResponseForEnvironment(endpointName, response);

		const jsonString = response.body;
		if (jsonString == null || jsonString === "") {
			if (allowParseFailure) {
				return responseInfo;
			}
			throw this.error("Empty response from the " + endpointName + " endpoint");
		}

		try {
			const jsonRoot = parseJson(jsonString);
			if (jsonRoot == null || (!isJsonObject(jsonRoot) && !isJsonArray(jsonRoot))) {
				if (allowParseFailure) {
					this.jsonObjectError = true;
					return responseInfo;
				}

				throw this.error(endpointName + " endpoint did not return a JSON object.", args("response", jsonString));
			}

			responseInfo["body_json"] = jsonRoot;
		} catch (e) {
			if (e instanceof JsonParseException) {
				if (allowParseFailure) {
					this.jsonParseError = true;
					this.jsonParseException = e; // save exception for later
					return responseInfo;
				}
				throw this.error(
					"Response from " + endpointName + " endpoint does not appear to be JSON.",
					e,
					args("response", jsonString),
				);
			}
			throw e;
		}

		return responseInfo;
	}

	protected handleJsonParseException(_env: Environment, e: JsonParseException): Environment {
		throw this.error("Error parsing " + this.endpointName + " response body as JSON", e);
	}

	protected handleRestClientResponseException(_env: Environment, e: RestClientResponseException): Environment {
		throw this.error(
			"RestClientResponseException occurred whilst calling " + this.endpointName,
			args("code", e.statusCode, "status", e.statusText, "body", e.responseBody),
		);
	}

	protected handleClientException(_env: Environment, e: HttpClientException): Environment {
		let msg = "Call to " + this.endpointName + " failed";
		const causeMessage = causeMessageOf(e);
		if (causeMessage != null) {
			msg += " - " + causeMessage;
		}
		throw this.error(msg, e);
	}
}
