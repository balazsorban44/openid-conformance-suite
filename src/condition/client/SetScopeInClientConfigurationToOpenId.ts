import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractSetScopeInClientConfiguration } from "./AbstractSetScopeInClientConfiguration.ts";

export class SetScopeInClientConfigurationToOpenId extends AbstractSetScopeInClientConfiguration {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		let scope = "openid";

		// This is necessary to allow the Australian ConnectID tests to run in our CI against Authlete;
		// in particular as the same Authlete server is supports multiple use cases just requesting
		// the 'openid' scope doesn't trigger FAPI2 behaviour; this override allows us to request
		// an additional scope that does enable FAPI2 behaviour
		const overrideScope = env.getString("client", "override_openid_scope");
		if (overrideScope != null) {
			scope = overrideScope;
		}

		return this.setScopeInClientConfiguration(env, scope);
	}
}
