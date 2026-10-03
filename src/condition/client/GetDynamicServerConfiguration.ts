import {
	AbstractCondition,
	args,
	HttpClientException,
	isJsonObject,
	JsonParseException,
	parseJson,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
	type JsonValue,
} from "../../framework/index.ts";

export class GetDynamicServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["config"] };
	static override post: EnvironmentRequirements = { required: ["server", "discovery_endpoint_response"] };

	protected getConfigurationEndpoint(): string {
		return "/.well-known/openid-configuration";
	}

	override async evaluate(env: Environment): Promise<Environment> {
		if (!env.containsObject("config")) {
			throw this.error("Couldn't find a configuration");
		}

		const staticIssuer = env.getString("config", "server.issuer");

		if (staticIssuer) {
			throw this.error(
				"Test set to use dynamic server configuration but test configuration contains static server configuration",
				args("issuer", staticIssuer),
			);
		}

		let discoveryUrl = env.getString("config", "server.discoveryUrl");

		if (!discoveryUrl) {
			const iss = env.getString("config", "server.discoveryIssuer");
			discoveryUrl = iss + this.getConfigurationEndpoint();

			if (!iss) {
				throw this.error("Couldn't find discoveryUrl or discoveryIssuer field for discovery purposes");
			}
		}

		// get out the server configuration component
		if (discoveryUrl) {
			// do an auto-discovery here

			// fetch the value
			let jsonString: string | null;
			// UPSTREAM: Java uses createRestTemplateWithCache(env) (opt-in cache via options.cache_external_metadata);
			// the TS framework has no cached HTTP client yet, so every fetch goes to the network.
			const client = this.createHttpClient(env);
			try {
				const response = await client.exchange({ url: discoveryUrl, method: "GET" });
				if (response.status >= 400) {
					// Java: RestTemplate throws RestClientResponseException on 4xx/5xx
					throw this.error(
						"Unable to fetch server configuration from " + discoveryUrl,
						new HttpClientException(response.status + " " + response.statusText + ": " + response.body),
					);
				}
				const responseInfo = this.convertResponseForEnvironment("discovery", response);

				env.putObject("discovery_endpoint_response", responseInfo);

				jsonString = response.body;
			} catch (e) {
				if (e instanceof HttpClientException) {
					const msg = "Unable to fetch server configuration from " + discoveryUrl + " - " + e.message;
					throw this.error(msg, e);
				}
				throw e;
			} finally {
				await client.close();
			}

			if (jsonString) {
				let parsed: JsonValue;
				try {
					parsed = parseJson(jsonString);
				} catch (e) {
					if (e instanceof JsonParseException) {
						throw this.error(e, args("json", jsonString));
					}
					throw e;
				}
				if (!isJsonObject(parsed)) {
					// Java: getAsJsonObject() throws IllegalStateException (not caught upstream)
					throw new Error("Not a JSON Object: " + JSON.stringify(parsed));
				}
				const serverConfig: JsonObject = parsed;

				this.logSuccess("Successfully parsed server configuration", serverConfig);

				env.putObject("server", serverConfig);

				return env;
			} else {
				throw this.error("empty server configuration");
			}
		} else {
			throw this.error("Couldn't find or construct a discovery URL");
		}
	}
}
