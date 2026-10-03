import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractJsonUriIsValidAndHttps } from "./AbstractJsonUriIsValidAndHttps.ts";

export class CheckDiscEndpointUserinfoEndpoint extends AbstractJsonUriIsValidAndHttps {
	private static readonly environmentVariable = "userinfo_endpoint";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(env, CheckDiscEndpointUserinfoEndpoint.environmentVariable);
	}
}
