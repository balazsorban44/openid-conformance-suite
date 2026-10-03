import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class UpdateClientAuthenticationAssertionClaimsWithISSAud extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client_assertion_claims"] };
	static override post: EnvironmentRequirements = { required: ["client_assertion_claims"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("client_assertion_claims") as JsonObject;

		this.updateAudience(claims, env);

		this.logSuccess("Updated audience in client assertion claims", claims);

		env.putObject("client_assertion_claims", claims);

		return env;
	}

	private updateAudience(claims: JsonObject, env: Environment): void {
		delete claims["aud"];

		const audience = env.getString("server", "issuer");
		if (!audience) {
			throw this.error("Couldn't find required configuration element", args("issuer", audience));
		}
		claims["aud"] = audience;
	}
}
