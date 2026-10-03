import {
	AbstractCondition,
	args,
	HttpClientException,
	JsonParseException,
	parseJsonObject,
	type Environment,
	type EnvironmentRequirements,
	type HttpClient,
	type JsonObject,
} from "../../framework/index.ts";

export class FetchClientKeys extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };
	static override post: EnvironmentRequirements = { required: ["client"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const jwksUri = env.getString("client", "jwks_uri");

		const client = env.getObject("client") as JsonObject;

		if ("jwks" in client) {
			throw this.error("Client already has a jwks", args("client", client));
		}

		if (jwksUri) {
			// do the fetch
			this.log("Fetching client keys", args("jwks_uri", jwksUri));

			let restTemplate: HttpClient;
			try {
				restTemplate = this.createRestTemplate(env);
			} catch (e) {
				throw this.error("Error creating HTTP client", e);
			}

			try {
				const response = await restTemplate.exchange({ url: jwksUri, method: "GET" });
				if (response.status >= 400) {
					// Java: RestTemplate throws a RestClientResponseException (which has no cause) for 4xx/5xx
					throw this.error(
						"Unable to fetch client keys from " + jwksUri,
						new Error(response.status + " " + response.statusText),
					);
				}
				const jwkString = response.body;

				this.log("Found JWK set string", args("jwk_string", jwkString));

				let jwkSet: JsonObject;
				try {
					jwkSet = parseJsonObject(jwkString ?? "");
				} catch (e) {
					if (e instanceof JsonParseException) {
						throw this.error("Client JWKs set string is not JSON", e);
					}
					throw e;
				}

				client["jwks"] = jwkSet;

				env.putObject("client", client);

				this.logSuccess("Downloaded and added client JWK set to client", args("client", client));

				return env;
			} catch (e) {
				if (e instanceof HttpClientException) {
					let msg = "Unable to fetch client keys from " + jwksUri;
					if (e.cause != null) {
						msg += " - " + (e.cause as Error).message;
					}
					throw this.error(msg, e);
				}
				throw e;
			} finally {
				await restTemplate.close();
			}
		} else {
			throw this.error("Didn't find a jwks_uri in client configuration");
		}
	}
}
