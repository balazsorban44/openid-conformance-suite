import { args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckIdTokenSignatureAlgorithm } from "./AbstractCheckIdTokenSignatureAlgorithm.ts";

export class CheckIdTokenSignatureAlgorithm extends AbstractCheckIdTokenSignatureAlgorithm {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request", "id_token"] };

	override evaluate(env: Environment): Environment {
		const requestedAlg = env.getString("dynamic_registration_request", "id_token_signed_response_alg");
		if (!requestedAlg) {
			throw this.error(
				"id_token_signed_response_alg not found in dynamic registration request",
				args("dynamic_registration_request", env.getObject("dynamic_registration_request")),
			);
		}

		return this.checkIdTokenSignatureAlgorithm(env, requestedAlg);
	}
}
