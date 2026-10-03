import {
	AbstractCondition,
	args,
	HttpClientException,
	mapToJsonObject,
	type Environment,
	type HttpRequest,
	type HttpResponse,
	type JsonObject,
} from "../../framework/index.ts";
import {
	causeMessageOf,
	checkResponseForError,
	IGNORE_ALL_ERRORS_HANDLER,
	type RestClientResponseException,
} from "./AbstractCallEndpoint.ts";

/** Java: org.springframework.http.HttpMethod */
export type HttpMethod = NonNullable<HttpRequest["method"]>;

export abstract class AbstractCallProtectedResource extends AbstractCondition {
	protected getAccessToken(env: Environment): string {
		const accessToken = env.getString("access_token", "value");
		if (!accessToken) {
			throw this.error("Access token not found");
		}

		const tokenType = env.getString("access_token", "type");
		if (!tokenType) {
			throw this.error("Token type not found");
		} else if (tokenType.toLowerCase() !== "bearer") {
			throw this.error("Access token is not a bearer token", args("token_type", tokenType));
		}

		return accessToken;
	}

	protected getUri(env: Environment): string {
		const resourceUri = env.getString("protected_resource_url");

		if (!resourceUri) {
			throw this.error("Missing Resource URL");
		}

		return resourceUri;
	}

	protected getMethod(env: Environment): HttpMethod {
		let resourceMethod: HttpMethod = "GET";
		const configuredMethod = env.getString("resource", "resourceMethod");
		if (configuredMethod) {
			resourceMethod = configuredMethod as HttpMethod;
		}

		return resourceMethod;
	}

	protected getHeaders(_env: Environment): Headers {
		return new Headers();
	}

	protected treatAllHttpStatusAsSuccess(): boolean {
		return false;
	}

	/** @returns the media type (Java: MediaType) */
	protected getContentType(_env: Environment): string {
		return "application/x-www-form-urlencoded";
	}

	/** @returns the media types (Java: List<MediaType>) */
	protected getAcceptContentType(_env: Environment): string[] {
		return ["application/json"];
	}

	/** @returns the request body (Java: Object): a string, or form parameters as URLSearchParams (Java: MultiValueMap) */
	protected getBody(env: Environment): string | URLSearchParams | null {
		const requestEntity = env.getString("resource_request_entity");
		return requestEntity;
	}

	protected async callProtectedResource(env: Environment): Promise<Environment> {
		const uri = this.getUri(env);

		const client = this.createHttpClient(env);
		try {
			const errorHandler = this.treatAllHttpStatusAsSuccess() ? IGNORE_ALL_ERRORS_HANDLER : null;

			const method = this.getMethod(env);
			const headers = this.getHeaders(env);

			if (!headers.has("accept")) {
				headers.set("accept", this.getAcceptContentType(env).join(", "));
			}

			if ((method === "POST" || method === "PUT" || method === "PATCH") && !headers.has("content-type")) {
				// See https://bitbucket.org/openid/connect/issues/1137/is-content-type-application-x-www-form
				headers.set("content-type", this.getContentType(env));
			}

			const body = this.getBody(env);

			let response: HttpResponse;
			try {
				response = await client.exchange({ url: uri, method, headers, body });
			} catch (e) {
				if (e instanceof HttpClientException) {
					let msg = "Call to protected resource " + uri + " failed";
					const causeMessage = causeMessageOf(e);
					if (causeMessage != null) {
						msg += " - " + causeMessage;
					}
					throw this.error(msg, e);
				}
				throw e;
			}

			const responseException = checkResponseForError(errorHandler, response);
			if (responseException != null) {
				return this.handleClientResponseException(env, responseException);
			}

			const responseCode: JsonObject = {};
			responseCode["code"] = response.status;
			const responseBody = response.body;
			const responseHeaders = mapToJsonObject(response.headers, true);
			let fullResponse: JsonObject;

			if (this.requireJsonResponseBody()) {
				fullResponse = this.convertJsonResponseForEnvironment("resource", response, this.allowJsonParseFailure());
			} else {
				fullResponse = this.convertResponseForEnvironment("resource", response);
			}

			return this.handleClientResponse(env, responseCode, responseBody, responseHeaders, fullResponse);
		} finally {
			await client.close();
		}
	}

	protected requireJsonResponseBody(): boolean {
		return false;
	}

	/**
	 * Only meaningful when {@link #requireJsonResponseBody()} is true. When set, a missing or unparseable
	 * body leaves body_json unset instead of failing the condition, so that {@link #handleClientResponse}
	 * still runs and a separate condition can report the problem at the severity the caller chose. Needed
	 * wherever the response may legitimately have no JSON body - e.g. a bodyless 401 carrying a DPoP
	 * use_dpop_nonce challenge (RFC9449-8.2).
	 */
	protected allowJsonParseFailure(): boolean {
		return false;
	}

	protected abstract handleClientResponse(
		env: Environment,
		responseCode: JsonObject,
		responseBody: string | null,
		responseHeaders: JsonObject,
		fullResponse: JsonObject,
	): Environment;

	protected handleClientResponseException(_env: Environment, e: RestClientResponseException): Environment {
		throw this.error("Unexpected error from the resource endpoint", args("code", e.statusCode, "status", e.statusText));
	}
}
