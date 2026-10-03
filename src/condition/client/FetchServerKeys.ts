import {
	AbstractCondition,
	args,
	HttpClientException,
	isJsonObject,
	JsonParseException,
	parseJson,
	type Environment,
	type EnvironmentRequirements,
	type JsonValue,
} from "../../framework/index.ts";

export class FetchServerKeys extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	static override post: EnvironmentRequirements = { required: ["server_jwks"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const jwksUri = env.getString("server", "jwks_uri");

		if (jwksUri) {
			// do the fetch

			this.log("Fetching server key", args("jwks_uri", jwksUri));

			const client = await this.createRestTemplateWithCache(env);
			try {
				let jwkString: string | null;
				try {
					const response = await client.exchange({ url: jwksUri, method: "GET" });
					if (response.status >= 400) {
						// Java: RestTemplate throws RestClientResponseException on 4xx/5xx
						throw this.error(
							"Fetching server keys from " + jwksUri + " failed",
							new HttpClientException(response.status + " " + response.statusText + ": " + response.body),
						);
					}
					jwkString = response.body;
				} catch (e) {
					if (e instanceof HttpClientException) {
						const msg = "Fetching server keys from " + jwksUri + " failed - " + e.message;
						throw this.error(msg, e);
					}
					throw e;
				}

				this.log("Found JWK set string", args("jwk_string", jwkString));

				let parsed: JsonValue;
				try {
					parsed = parseJson(jwkString as string);
				} catch (e) {
					if (e instanceof JsonParseException) {
						throw this.error("Server JWKs set string is not JSON", e);
					}
					throw e;
				}
				if (!isJsonObject(parsed)) {
					// Java: getAsJsonObject() throws IllegalStateException (not caught upstream)
					throw new Error("Not a JSON Object: " + JSON.stringify(parsed));
				}
				const jwkSet = parsed;
				env.putObject("server_jwks", jwkSet);

				this.logSuccess("Found server JWK set", args("server_jwks", jwkSet));
				return env;
			} finally {
				await client.close();
			}
		} else {
			throw this.error("Didn't find jwks_uri in the server configuration");
		}
	}
}
