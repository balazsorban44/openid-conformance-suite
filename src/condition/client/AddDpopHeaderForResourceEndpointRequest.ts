import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddDpopHeaderForResourceEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = {
		required: ["resource_endpoint_request_headers"],
		strings: ["dpop_proof"],
	};

	override evaluate(env: Environment): Environment {
		const dpopProof = env.getString("dpop_proof") as string;

		const requestHeaders = env.getObject("resource_endpoint_request_headers") as JsonObject;

		requestHeaders["DPoP"] = dpopProof;

		this.logSuccess("Set DPoP header", args("DPoP", dpopProof));

		return env;
	}
}
