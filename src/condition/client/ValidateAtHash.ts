import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateHash } from "./AbstractValidateHash.ts";

export class ValidateAtHash extends AbstractValidateHash {
	static override pre: EnvironmentRequirements = { required: ["access_token", "at_hash"] };

	override evaluate(env: Environment): Environment {
		return super.validateHash(env, "at_hash", "at_hash");
	}
}
