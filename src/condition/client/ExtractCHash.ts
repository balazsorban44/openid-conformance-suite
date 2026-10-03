import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { ExtractHash } from "./ExtractHash.ts";

export class ExtractCHash extends ExtractHash {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };
	static override post: EnvironmentRequirements = { required: ["c_hash"] };

	override evaluate(env: Environment): Environment {
		return super.extractHash(env, "c_hash", "c_hash");
	}
}
