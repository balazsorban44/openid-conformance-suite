import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import type { JWK } from "../../util/JWKUtil.ts";
import { AbstractSignJWT } from "./AbstractSignJWT.ts";

export class SignRequestObject extends AbstractSignJWT {
	static override pre: EnvironmentRequirements = { required: ["request_object_claims", "client_jwks"] };
	static override post: EnvironmentRequirements = { strings: ["request_object"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const claims = env.getObject("request_object_claims");
		const jwks = env.getObject("client_jwks");
		return await this.signJWT(env, claims, jwks);
	}

	protected override logSuccessByJWTType(
		env: Environment,
		claimSet: JsonObject | null,
		jwk: JWK | null,
		header: JsonObject | null,
		jws: string,
		verifiableObj: JsonObject | null,
	): void {
		env.putString("request_object", jws);
		this.logSuccess(
			"Signed the request object",
			args("request_object", verifiableObj, "header", header, "claims", claimSet, "key", jwk),
		);
	}
}
