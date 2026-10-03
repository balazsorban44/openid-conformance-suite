import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import type { JWK } from "../../../util/JWKUtil.ts";
import { OIDCCSignLogoutToken } from "./OIDCCSignLogoutToken.ts";

export class OIDCCSignLogoutTokenWithWrongAlgorithm extends OIDCCSignLogoutToken {
	static override pre: EnvironmentRequirements = {
		required: ["logout_token_claims", "server_jwks", "client"],
		strings: ["signing_algorithm"],
	};
	static override post: EnvironmentRequirements = { strings: ["logout_token"] };

	override async evaluate(env: Environment): Promise<Environment> {
		return await super.evaluate(env);
	}

	protected override getAlg(env: Environment): string {
		let signingAlg = env.getString("client", "id_token_signed_response_alg");
		if (signingAlg == null || signingAlg.length === 0) {
			//use the default
			signingAlg = env.getString("signing_algorithm");
		}
		if ("RS256" === signingAlg) {
			return "ES256";
		} else {
			return "RS256";
		}
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
			"Signed the logout token with a wrong algorithm",
			args(
				"logout_token",
				verifiableObj != null ? verifiableObj : jws,
				"algorithm",
				header != null ? header["alg"] : "none",
				"configured_algorithm",
				super.getAlg(env),
				"key",
				jwk != null ? JSON.stringify(jwk) : "none",
			),
		);
	}
}
