import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

export class EnsureRequestObjectSigningAlgIsRS256InClientMetadata extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const alg = this.getRequestObjectSigningAlg();

		if ("RS256" === alg) {
			this.logSuccess("request_object_signing_alg is RS256");
			return env;
		}
		throw this.error(
			"Unexpected request_object_signing_alg. RS256 is required for this test.",
			args("actual", alg, "expected", "RS256"),
		);
	}
}
