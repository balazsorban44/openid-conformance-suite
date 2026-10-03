import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetDpopHtmHtuForResourceEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["dpop_proof_claims"],
		strings: ["protected_resource_url"],
	};

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("dpop_proof_claims") as JsonObject;

		const resourceEndpoint = env.getString("protected_resource_url");

		let resourceMethod = "GET";
		const configuredMethod = env.getString("resource", "resourceMethod");
		if (configuredMethod) {
			resourceMethod = configuredMethod;
		}

		claims["htm"] = resourceMethod;
		claims["htu"] = resourceEndpoint;

		this.logSuccess("Added htm/htu to DPoP proof claims", claims);

		return env;
	}
}
