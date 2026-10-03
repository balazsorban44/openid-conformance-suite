import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";

export class OIDCCAddRequestObjectSigningAlgValuesSupportedToServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	static override post: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;

		const signingAlgValuesSupported: JsonArray = [];
		signingAlgValuesSupported.push("none");
		signingAlgValuesSupported.push("RS256");
		signingAlgValuesSupported.push("PS256");
		signingAlgValuesSupported.push("ES256");
		signingAlgValuesSupported.push("EdDSA");

		server["request_object_signing_alg_values_supported"] = signingAlgValuesSupported;

		this.log("Added request_object_signing_alg_values_supported to server configuration", args("server", server));

		return env;
	}
}
