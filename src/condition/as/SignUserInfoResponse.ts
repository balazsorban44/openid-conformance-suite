import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import type { JWK } from "../../util/JWKUtil.ts";
import { AbstractSignJWT } from "../client/AbstractSignJWT.ts";

export class SignUserInfoResponse extends AbstractSignJWT {
	static override pre: EnvironmentRequirements = { required: ["user_info_endpoint_response", "server_jwks", "client"] };
	static override post: EnvironmentRequirements = { strings: ["signed_user_info_endpoint_response"] };

	/**
	 * Requires userinfo_signed_response_alg. Use with skipIfElementMissing
	 *
	 * @param env
	 * @return
	 */
	override async evaluate(env: Environment): Promise<Environment> {
		const claims = env.getObject("user_info_endpoint_response") as JsonObject;
		const jwks = env.getObject("server_jwks");
		const signingAlg = env.getString("client", "userinfo_signed_response_alg") as string;
		if ("none" === signingAlg) {
			const signed = this.signWithAlgNone(JSON.stringify(claims));
			this.logSuccess("Signed the userinfo response with alg none", args("userinfo", signed));
			env.putString("signed_user_info_endpoint_response", signed);
			return env;
		} else {
			const client = env.getObject("client");

			const selectedKey = this.selectOrCreateKey(jwks, signingAlg, client);
			env = await this.signJWTUsingKey(env, claims, selectedKey, signingAlg);
			return env;
		}
	}

	protected override logSuccessByJWTType(
		env: Environment,
		_claimSet: JsonObject | null,
		_jwk: JWK | null,
		_header: JsonObject | null,
		jws: string,
		verifiableObj: JsonObject | null,
	): void {
		env.putString("signed_user_info_endpoint_response", jws);
		this.logSuccess("Signed the userinfo response", args("userinfo", verifiableObj));
	}
}
