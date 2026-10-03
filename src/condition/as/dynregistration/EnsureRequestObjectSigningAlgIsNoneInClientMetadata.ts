import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

export class EnsureRequestObjectSigningAlgIsNoneInClientMetadata extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const alg = this.getRequestObjectSigningAlg();

		if ("none" === alg) {
			this.logSuccess("request_object_signing_alg is none");
			return env;
		}
		throw this.error(
			"Unexpected request_object_signing_alg. 'none' is required for this test.",
			args("actual", alg, "expected", "none"),
		);
	}
}
