import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractSignClaimsWithNullAlgorithm } from "../common/AbstractSignClaimsWithNullAlgorithm.ts";

export class SerializeRequestObjectWithNullAlgorithm extends AbstractSignClaimsWithNullAlgorithm {
	static override pre: EnvironmentRequirements = { required: ["request_object_claims"] };
	static override post: EnvironmentRequirements = { strings: ["request_object"] };

	protected override getClaimsNotFoundErrorMsg(): string {
		return "Couldn't find request object claims";
	}

	protected override getSuccessMsg(): string {
		return "Serialized the request object";
	}

	override evaluate(env: Environment): Environment {
		return this.signWithNullAlgorithm(env, "request_object_claims", "request_object");
	}
}
