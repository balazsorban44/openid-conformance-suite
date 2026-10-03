import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import type { JWK } from "../../../util/JWKUtil.ts";
import { AbstractSignJWT } from "../../client/AbstractSignJWT.ts";

export class OIDCCSignLogoutToken extends AbstractSignJWT {
	static override pre: EnvironmentRequirements = {
		required: ["logout_token_claims", "server_jwks", "client"],
		strings: ["signing_algorithm"],
	};
	static override post: EnvironmentRequirements = { strings: ["logout_token"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const claims = env.getObject("logout_token_claims");
		const jwks = env.getObject("server_jwks");
		const signingAlg = this.getAlg(env);
		const client = env.getObject("client");

		const selectedKey = this.selectOrCreateKey(jwks, signingAlg, client);
		await this.signJWTUsingKey(env, claims, selectedKey, signingAlg);

		return env;
	}

	protected getAlg(env: Environment): string {
		let signingAlg = env.getString("client", "id_token_signed_response_alg");
		if (signingAlg == null || signingAlg.length === 0) {
			//use the default
			signingAlg = env.getString("signing_algorithm") as string;
		}

		if ("none" === signingAlg) {
			throw this.error("Algorithm 'none' cannot be used for logout tokens");
		}
		return signingAlg;
	}

	protected override logSuccessByJWTType(
		env: Environment,
		_claimSet: JsonObject | null,
		jwk: JWK | null,
		header: JsonObject | null,
		jws: string,
		verifiableObj: JsonObject | null,
	): void {
		env.putString("logout_token", jws);
		this.logSuccess(
			"Signed the logout token",
			args(
				"logout_token",
				verifiableObj != null ? verifiableObj : jws,
				"algorithm",
				header != null ? header["alg"] : "none",
				"key",
				jwk != null ? JSON.stringify(jwk) : "none",
			),
		);
	}
}
