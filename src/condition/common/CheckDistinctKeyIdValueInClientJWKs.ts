import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckDistinctKeyIdValueInJWKs } from "./AbstractCheckDistinctKeyIdValueInJWKs.ts";

export class CheckDistinctKeyIdValueInClientJWKs extends AbstractCheckDistinctKeyIdValueInJWKs {
	static override pre: EnvironmentRequirements = { required: ["client_jwks"] };

	override evaluate(env: Environment): Environment {
		return this.checkDistinctKeyIdValueInJWKs(env, "client_jwks");
	}
}
