import {
	AbstractCondition,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ChangeTokenEndpointInServerConfigurationToMtls extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"], strings: ["base_url", "base_mtls_url"] };
	static override post: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;
		const baseUrl = env.getString("base_url") as string;
		const baseMtlsUrl = env.getString("base_mtls_url");

		let tokenEndpoint = OIDFJSON.getString(server["token_endpoint"]);
		if (tokenEndpoint.startsWith(baseUrl)) {
			//grab the path from base url part and prefix with mtls path
			tokenEndpoint = baseMtlsUrl + tokenEndpoint.substring(baseUrl.length);
		}
		server["token_endpoint"] = tokenEndpoint;
		this.log("Replaced token_endpoint with the MTLS one");
		return env;
	}
}
