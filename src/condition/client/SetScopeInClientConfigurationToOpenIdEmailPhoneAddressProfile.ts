import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractSetScopeInClientConfiguration } from "./AbstractSetScopeInClientConfiguration.ts";

export class SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile extends AbstractSetScopeInClientConfiguration {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		return this.setScopeInClientConfiguration(env, "openid email phone address profile");
	}
}
