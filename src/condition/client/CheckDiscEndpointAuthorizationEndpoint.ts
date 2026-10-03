import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractJsonUriIsValidAndHttps } from "./AbstractJsonUriIsValidAndHttps.ts";

export class CheckDiscEndpointAuthorizationEndpoint extends AbstractJsonUriIsValidAndHttps {
	private static readonly environmentVariable = "authorization_endpoint";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(env, CheckDiscEndpointAuthorizationEndpoint.environmentVariable);
	}
}
