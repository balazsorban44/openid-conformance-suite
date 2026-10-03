import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckDistinctKeyIdValueInJWKs } from "./AbstractCheckDistinctKeyIdValueInJWKs.ts";

export class CheckDistinctKeyIdValueInServerJWKs extends AbstractCheckDistinctKeyIdValueInJWKs {
	static override pre: EnvironmentRequirements = { required: ["server_jwks"] };

	override evaluate(env: Environment): Environment {
		return this.checkDistinctKeyIdValueInJWKs(env, "server_jwks");
	}
}
