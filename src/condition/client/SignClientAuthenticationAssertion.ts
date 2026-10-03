import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import type { JWK } from "../../util/JWKUtil.ts";
import { AbstractSignJWT } from "./AbstractSignJWT.ts";

export class SignClientAuthenticationAssertion extends AbstractSignJWT {
	static override pre: EnvironmentRequirements = { required: ["client_assertion_claims", "client_jwks"] };
	static override post: EnvironmentRequirements = { strings: ["client_assertion"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const claims = env.getObject("client_assertion_claims");
		const jwks = env.getObject("client_jwks");
		return await this.signJWT(env, claims, jwks);
	}

	protected override logSuccessByJWTType(
		env: Environment,
		_claimSet: JsonObject | null,
		_jwk: JWK | null,
		_header: JsonObject | null,
		jws: string,
		verifiableObj: JsonObject | null,
	): void {
		env.putString("client_assertion", jws);
		this.logSuccess("Signed the client assertion", args("client_assertion", verifiableObj));
	}
}
