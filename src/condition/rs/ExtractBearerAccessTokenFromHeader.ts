import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ExtractBearerAccessTokenFromHeader extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["incoming_request"] };
	static override post: EnvironmentRequirements = { strings: ["incoming_access_token"] };

	override evaluate(env: Environment): Environment {
		const auth = env.getString("incoming_request", "headers.authorization");

		if (auth) {
			if (auth.toLowerCase().startsWith("bearer") && auth.length > "bearer ".length) {
				const incoming = auth.substring("bearer ".length);
				if (incoming) {
					this.logSuccess("Found access token on incoming request", args("access_token", incoming));
					env.putString("incoming_access_token", incoming);
					return env;
				} else {
					throw this.error("Couldn't find access token in header");
				}
			} else {
				throw this.error("Couldn't find bearer token in authorization header");
			}
		} else {
			throw this.error("Couldn't find authorization header");
		}
	}
}
