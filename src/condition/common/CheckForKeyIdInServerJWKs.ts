import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckForKeyIdinJWKs } from "./AbstractCheckForKeyIdinJWKs.ts";

export class CheckForKeyIdInServerJWKs extends AbstractCheckForKeyIdinJWKs {
	static override pre: EnvironmentRequirements = { required: ["server_jwks"] };

	override evaluate(env: Environment): Environment {
		return this.checkForKeyIdInJWKs(env, "server_jwks");
	}
}
