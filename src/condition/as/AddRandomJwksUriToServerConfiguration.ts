import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddRandomJwksUriToServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"], strings: ["random_jwks_uri_suffix"] };
	static override post: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;

		const currentJwksUri = OIDFJSON.getString(server["jwks_uri"]);
		const randomSuffix = env.getString("random_jwks_uri_suffix");
		const newJwksUri = currentJwksUri + randomSuffix;
		server["jwks_uri"] = newJwksUri;
		env.putObject("server", server);
		this.log("Added random jwks_uri to server configuration", args("jwks_uri", newJwksUri));

		return env;
	}
}
