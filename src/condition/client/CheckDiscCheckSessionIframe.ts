import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractJsonUriIsValidAndHttps } from "./AbstractJsonUriIsValidAndHttps.ts";

export class CheckDiscCheckSessionIframe extends AbstractJsonUriIsValidAndHttps {
	private static readonly environmentVariable = "check_session_iframe";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return this.validate(env, CheckDiscCheckSessionIframe.environmentVariable);
	}
}
