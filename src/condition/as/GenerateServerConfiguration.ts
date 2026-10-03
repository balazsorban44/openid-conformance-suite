import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class GenerateServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { required: ["server"], strings: ["issuer", "discoveryUrl"] };

	override evaluate(env: Environment): Environment {
		let baseUrl = env.getString("base_url") as string;

		if (baseUrl.length === 0) {
			throw this.error("Base URL is empty");
		}

		// set off the URLs below with a slash, if needed
		if (!baseUrl.endsWith("/")) {
			baseUrl = baseUrl + "/";
		}

		this.createBaseConfiguration(env, baseUrl);

		this.logSuccess(
			"Created server configuration",
			args(
				"server",
				env.getObject("server"),
				"issuer",
				env.getString("issuer"),
				"discoveryUrl",
				env.getString("discoveryUrl"),
			),
		);

		return env;
	}

	protected createBaseConfiguration(env: Environment, baseUrl: string): void {
		// create a base server configuration object based on the base URL
		const server: JsonObject = {};

		server["issuer"] = baseUrl;
		server["authorization_endpoint"] = baseUrl + "authorize";
		server["token_endpoint"] = baseUrl + "token";
		server["jwks_uri"] = baseUrl + "jwks";
		// add this as the server configuration
		env.putObject("server", server);

		env.putString("issuer", baseUrl);
		env.putString("discoveryUrl", baseUrl + ".well-known/openid-configuration");
	}
}
