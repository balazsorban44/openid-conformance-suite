import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { ExtractHash } from "./ExtractHash.ts";

export class ExtractAtHash extends ExtractHash {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };
	static override post: EnvironmentRequirements = { required: ["at_hash"] };

	override evaluate(env: Environment): Environment {
		return super.extractHash(env, "at_hash", "at_hash");
	}
}
