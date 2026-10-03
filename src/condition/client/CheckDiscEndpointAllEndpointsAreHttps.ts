import type { Environment, EnvironmentRequirements, JsonObject } from "../../framework/index.ts";
import { AbstractJsonUriIsValidAndHttps } from "./AbstractJsonUriIsValidAndHttps.ts";

export class CheckDiscEndpointAllEndpointsAreHttps extends AbstractJsonUriIsValidAndHttps {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const discoveryDoc = env.getObject("server") as JsonObject;

		for (const key of Object.keys(discoveryDoc)) {
			if (key.endsWith("_endpoint")) {
				env = this.validate(env, key);
			}
		}
		return env;
	}
}
