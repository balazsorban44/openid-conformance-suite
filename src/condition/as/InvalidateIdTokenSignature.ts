import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractInvalidateJwsSignature } from "../common/AbstractInvalidateJwsSignature.ts";

export class InvalidateIdTokenSignature extends AbstractInvalidateJwsSignature {
	static override pre: EnvironmentRequirements = { strings: ["id_token"] };
	static override post: EnvironmentRequirements = { strings: ["id_token"] };

	override evaluate(env: Environment): Environment {
		return this.invalidateSignature(env, "id_token");
	}
}
