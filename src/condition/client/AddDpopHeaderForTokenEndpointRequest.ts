import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class AddDpopHeaderForTokenEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["dpop_proof"] };
	static override post: EnvironmentRequirements = { required: ["token_endpoint_request_headers"] };

	override evaluate(env: Environment): Environment {
		const dpopProof = env.getString("dpop_proof") as string;

		let headers = env.getObject("token_endpoint_request_headers");

		if (headers == null) {
			headers = {};
			env.putObject("token_endpoint_request_headers", headers);
		}

		headers["DPoP"] = dpopProof;

		this.logSuccess("Set DPoP header", args("DPoP", dpopProof));

		return env;
	}
}
