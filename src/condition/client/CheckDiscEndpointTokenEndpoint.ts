import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractJsonUriIsValidAndHttps } from "./AbstractJsonUriIsValidAndHttps.ts";

export class CheckDiscEndpointTokenEndpoint extends AbstractJsonUriIsValidAndHttps {
	private static readonly environmentVariable = "token_endpoint";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(env, CheckDiscEndpointTokenEndpoint.environmentVariable);
	}
}
