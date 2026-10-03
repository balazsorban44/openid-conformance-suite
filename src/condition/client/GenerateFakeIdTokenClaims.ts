import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class GenerateFakeIdTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client", "server"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const serverIssuerUrl = env.getString("server", "issuer");
		const clientId = env.getString("client", "client_id");

		if (!serverIssuerUrl) {
			throw this.error("Couldn't find issuer");
		}

		if (!clientId) {
			throw this.error("Couldn't find client ID");
		}

		const claims: JsonObject = {};
		// aud/iss are deliberately the "wrong" way around here; this is an id_token "issued" by the client
		claims["iss"] = clientId;
		claims["sub"] = "SubjectID";
		claims["aud"] = serverIssuerUrl;

		claims["nonce"] = "flibble";

		const iat = Math.floor(Date.now() / 1000);
		const exp = iat + 5 * 60;

		claims["iat"] = iat;
		claims["exp"] = exp;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Created ID Token Claims", claims);

		return env;
	}
}
