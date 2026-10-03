import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";

export class SetTokenEndpointAuthMethodsSupportedToTlsClientAuthOnly extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	static override post: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const data: JsonArray = [];
		data.push("tls_client_auth");

		const server = env.getObject("server") as JsonObject;
		server["token_endpoint_auth_methods_supported"] = data;
		env.putObject("server", server);

		this.log(
			"Changed token_endpoint_auth_methods_supported to tls_client_auth only in server configuration",
			args("server_configuration", server),
		);

		return env;
	}
}
