import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class GenerateIdTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["user_info", "client"], strings: ["issuer"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const subject = env.getString("user_info", "sub");
		const issuer = env.getString("issuer");
		const clientId = env.getString("client", "client_id");
		const nonce = env.getString("nonce");

		if (!subject) {
			throw this.error("Couldn't find subject");
		}

		if (!issuer) {
			throw this.error("Couldn't find issuer");
		}

		if (!clientId) {
			throw this.error("Couldn't find client ID");
		}

		const claims: JsonObject = {};
		claims["iss"] = issuer;
		claims["sub"] = subject;
		claims["aud"] = clientId;
		if (nonce) {
			claims["nonce"] = nonce;
		}

		// Instants are represented as epoch seconds
		const iat = Math.floor(Date.now() / 1000);
		const exp = this.getExp(iat);

		claims["iat"] = iat;
		claims["exp"] = exp;

		env.putObject("id_token_claims", claims);

		this.logSuccess("Created ID Token Claims", claims);

		return env;
	}

	protected getExp(iat: number): number {
		return iat + 5 * 60;
	}
}
