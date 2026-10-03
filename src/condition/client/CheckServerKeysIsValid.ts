import { args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractLenientJwksCondition } from "../AbstractLenientJwksCondition.ts";
import { ParseException } from "../../util/JWKUtil.ts";

export class CheckServerKeysIsValid extends AbstractLenientJwksCondition {
	static override pre: EnvironmentRequirements = { required: ["server_jwks"] };

	override evaluate(env: Environment): Environment {
		const serverJWKs = env.getObject("server_jwks");
		if (serverJWKs == null) {
			throw this.error("Couldn't find server JWKs");
		}

		try {
			// parse to make sure it's really a JWK set; individual keys the JOSE library cannot use
			// are logged and skipped, as a recipient ignores them (RFC 7517 section 5)
			this.parseJwksLenientlyLoggingSkips(JSON.stringify(serverJWKs), "server");
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Unable to parse JWK set", e);
			}
			throw e;
		}

		this.logSuccess("Server JWKs is valid", args("server_jwks", serverJWKs));

		return env;
	}
}
