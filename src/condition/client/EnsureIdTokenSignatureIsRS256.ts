import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckIdTokenSignatureAlgorithm } from "./AbstractCheckIdTokenSignatureAlgorithm.ts";

export class EnsureIdTokenSignatureIsRS256 extends AbstractCheckIdTokenSignatureAlgorithm {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		return this.checkIdTokenSignatureAlgorithm(env, "RS256");
	}
}
