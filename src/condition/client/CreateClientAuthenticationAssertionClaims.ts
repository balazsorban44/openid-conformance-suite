import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateClientAuthenticationAssertionClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client", "server"] };
	static override post: EnvironmentRequirements = { required: ["client_assertion_claims"] };

	override evaluate(env: Environment): Environment {
		const client_id = env.getString("client", "client_id");

		if (!client_id) {
			throw this.error("Couldn't find required configuration element", args("client_id", client_id));
		}

		const claims: JsonObject = {};

		claims["iss"] = client_id;
		claims["sub"] = client_id;

		// This code uses the mtls aliased token endpoint if there is one
		// This is probably not correct, according to this ticket we should always use the non-MTLS one:
		// https://bitbucket.org/openid/mobile/issues/203/mtls-aliases-ambiguity-in-private_key_jwt
		// This probably only matters in FAPI tests, as they are the only case where we need to apply the
		// mtls aliases when using private_key_jwt (due to the requirement for mtls sender constrained access tokens).
		// Arguably the MTLS aliases value is still acceptable when we are sending the assertion to the MTLS aliased
		// token endpoint, but we may want to check that the non-MTLS value is also accepted.
		const audience =
			env.getString("token_endpoint") != null
				? env.getString("token_endpoint")
				: env.getString("server", "token_endpoint");

		if (!audience) {
			throw this.error("Couldn't find required configuration element", args("audience", audience));
		}

		claims["aud"] = audience;
		claims["jti"] = RandomStringUtils.nextAlphanumeric(20);

		const iat = Math.floor(Date.now() / 1000);
		const exp = iat + 60;

		claims["nbf"] = iat;
		claims["iat"] = iat;
		claims["exp"] = exp;

		this.logSuccess("Created client assertion claims", claims);

		env.putObject("client_assertion_claims", claims);

		return env;
	}
}
