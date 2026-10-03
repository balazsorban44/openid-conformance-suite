import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateHash } from "./AbstractValidateHash.ts";

export class ValidateCHash extends AbstractValidateHash {
	static override pre: EnvironmentRequirements = { required: ["c_hash", "authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		return super.validateHash(env, "c_hash", "c_hash");
	}
}
