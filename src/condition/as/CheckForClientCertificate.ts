import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class CheckForClientCertificate extends AbstractCondition {
	// note, we don't use the @PreEnvironment check here so we can do a more direct check below
	override evaluate(env: Environment): Environment {
		if (env.containsObject("client_certificate")) {
			this.logSuccess("Found client certificate");
			return env;
		} else {
			throw this.error("Client certificate not found");
		}
	}
}
