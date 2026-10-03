import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import type { JWK } from "../../../util/JWKUtil.ts";
import { AbstractSignJWT } from "../../client/AbstractSignJWT.ts";

export class OIDCCSignLogoutTokenWithAlgNone extends AbstractSignJWT {
	static override pre: EnvironmentRequirements = { required: ["logout_token_claims"] };
	static override post: EnvironmentRequirements = { strings: ["logout_token"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("logout_token_claims") as JsonObject;
		const signed = this.signWithAlgNone(JSON.stringify(claims));
		this.logSuccessByJWTType(env, null, null, null, signed, null);
		env.putString("logout_token", signed);
		return env;
	}

	protected override logSuccessByJWTType(
		env: Environment,
		_claimSet: JsonObject | null,
		_jwk: JWK | null,
		_header: JsonObject | null,
		jws: string,
		verifiableObj: JsonObject | null,
	): void {
		env.putString("logout_token", jws);
		this.logSuccess(
			"Signed the logout token using algorithm 'none'",
			args("logout_token", verifiableObj != null ? verifiableObj : jws, "algorithm", "none"),
		);
	}
}
