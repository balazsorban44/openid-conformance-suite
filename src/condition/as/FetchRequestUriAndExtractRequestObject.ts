import { errors } from "jose";
import {
	AbstractCondition,
	args,
	HttpClientException,
	JsonParseException,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";
import { JOSEException } from "../../util/JWEUtil.ts";
import { JWTUtil, ParseException } from "../../util/JWTUtil.ts";

export class FetchRequestUriAndExtractRequestObject extends AbstractCondition {
	// server_encryption_keys is only consulted when the fetched request object is encrypted (see
	// JWTUtil.jwtStringToJsonObjectForEnvironment); it is therefore not required here. Callers that
	// never receive an encrypted request object (e.g. the OID4VP verifier, where the wallet has no
	// way to publish an encryption key to the verifier) need not generate it.
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_http_request_params"] };
	static override post: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const requestParams = env.getObject("authorization_endpoint_http_request_params");
		const requestUri = env.getString("authorization_endpoint_http_request_params", "request_uri");
		if (requestUri) {
			this.log("Fetching request object from request_uri", args("request_uri", requestUri));
			let requestObjectString: string | null = "";
			const client = env.getObject("client");
			const serverEncKeys = env.getObject("server_encryption_keys");
			const restTemplate = this.createRestTemplate(env);
			try {
				const response = await restTemplate.exchange({ url: requestUri, method: "GET" });
				// RestTemplate.getForObject throws a RestClientException (with no cause) for 4xx/5xx responses
				if (response.status >= 400) {
					throw new HttpClientException(
						response.status +
							" " +
							response.statusText +
							": " +
							(response.body ? '"' + response.body + '"' : "[no body]"),
					);
				}

				requestObjectString = response.body;

				this.log("Downloaded request object", args("request_object", requestObjectString));

				//request object will be decrypted if it's encrypted
				// UPSTREAM: an empty response body makes Java throw a NullPointerException here
				const jsonObjectForJwt = await JWTUtil.jwtStringToJsonObjectForEnvironment(
					requestObjectString as string,
					client,
					serverEncKeys,
				);

				env.putObject("authorization_request_object", jsonObjectForJwt);

				this.logSuccess("Parsed request object", jsonObjectForJwt);

				return env;
			} catch (e) {
				if (e instanceof HttpClientException) {
					let msg = "Unable to fetch request_uri from " + requestUri;
					// Java: ResourceAccessException (I/O errors) has the underlying exception as its cause
					const cause = e.cause instanceof Error ? (e.cause.cause instanceof Error ? e.cause.cause : e.cause) : null;
					if (cause != null) {
						msg += " - " + cause.message;
					}
					throw this.error(msg, e);
				}
				if (e instanceof JsonParseException) {
					throw this.error("Response is not JSON", e);
				}
				if (e instanceof ParseException) {
					throw this.error("Couldn't parse request object", e, args("request", requestObjectString));
				}
				if (e instanceof JOSEException || e instanceof errors.JOSEError) {
					throw this.error(
						"Couldn't decrypt request object",
						e,
						args("request", requestObjectString, "keys", serverEncKeys),
					);
				}
				throw e;
			} finally {
				await restTemplate.close();
			}
		} else {
			throw this.error(
				"Authorization endpoint request does not contain a request_uri parameter",
				args("authorization_endpoint_http_request_params", requestParams),
			);
		}
	}
}
