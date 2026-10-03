import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetDpopProofNonceForResourceEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dpop_proof_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("dpop_proof_claims") as JsonObject;

		const nonce = env.getString("resource_server_dpop_nonce");

		if (nonce) {
			claims["nonce"] = nonce;
			this.logSuccess("Added nonce to DPoP proof claims", args("DPoP nonce", nonce));
		} else {
			throw this.error("resource_server_dpop_nonce not found");
		}
		return env;
	}
}
