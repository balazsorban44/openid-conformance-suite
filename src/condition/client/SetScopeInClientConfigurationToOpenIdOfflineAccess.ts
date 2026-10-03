import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractSetScopeInClientConfiguration } from "./AbstractSetScopeInClientConfiguration.ts";

export class SetScopeInClientConfigurationToOpenIdOfflineAccess extends AbstractSetScopeInClientConfiguration {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		return this.setScopeInClientConfiguration(env, "openid offline_access", " so that a refresh token is issued");
	}
}
