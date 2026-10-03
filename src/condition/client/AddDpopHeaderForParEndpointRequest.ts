import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class AddDpopHeaderForParEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["dpop_proof"] };
	static override post: EnvironmentRequirements = {
		required: ["pushed_authorization_request_endpoint_request_headers"],
	};

	override evaluate(env: Environment): Environment {
		const dpopProof = env.getString("dpop_proof") as string;

		let headers = env.getObject("pushed_authorization_request_endpoint_request_headers");

		if (headers == null) {
			headers = {};
			env.putObject("pushed_authorization_request_endpoint_request_headers", headers);
		}

		headers["DPoP"] = dpopProof;

		this.logSuccess("Set DPoP header for PAR endpoint", args("DPoP", dpopProof));

		return env;
	}
}
