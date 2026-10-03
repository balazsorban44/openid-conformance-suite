import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import type { JWK } from "../../util/JWKUtil.ts";
import { AbstractSignJWT } from "../client/AbstractSignJWT.ts";

export class OIDCCSignIdToken extends AbstractSignJWT {
	static override pre: EnvironmentRequirements = {
		required: ["id_token_claims", "server_jwks", "client"],
		strings: ["signing_algorithm"],
	};
	static override post: EnvironmentRequirements = { strings: ["id_token"], required: ["all_issued_id_tokens"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const claims = env.getObject("id_token_claims") as JsonObject;
		const jwks = env.getObject("server_jwks");
		let signingAlg = env.getString("client", "id_token_signed_response_alg");
		if (signingAlg == null || signingAlg.length === 0) {
			//use the default
			signingAlg = env.getString("signing_algorithm") as string;
		}
		const client = env.getObject("client");
		if ("none" === signingAlg) {
			const signed = this.signWithAlgNone(JSON.stringify(claims));
			this.logSuccessByJWTType(env, null, null, null, signed, null);
		} else {
			const selectedKey = this.selectOrCreateKey(jwks, signingAlg, client);
			await this.signJWTUsingKey(env, claims, selectedKey, signingAlg);
		}
		//keep track of all issued id_tokens to be used for logout
		const idToken = env.getString("id_token") as string;
		if (!env.containsObject("all_issued_id_tokens")) {
			const allIdTokens: JsonObject = {};
			env.putObject("all_issued_id_tokens", allIdTokens);
		}
		const allIdTokens = env.getObject("all_issued_id_tokens") as JsonObject;
		//because you can't add JsonArrays to env
		allIdTokens[idToken] = "1";

		return env;
	}

	protected override logSuccessByJWTType(
		env: Environment,
		_claimSet: JsonObject | null,
		jwk: JWK | null,
		header: JsonObject | null,
		jws: string,
		verifiableObj: JsonObject | null,
	): void {
		env.putString("id_token", jws);
		this.logSuccess(
			"Signed the ID token",
			args(
				"id_token",
				verifiableObj != null ? verifiableObj : jws,
				"algorithm",
				header != null ? header["alg"] : "none",
				"key",
				jwk != null ? JSON.stringify(jwk) : "none",
			),
		);
	}
}
