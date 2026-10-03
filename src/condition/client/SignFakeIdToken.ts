import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import type { JWK } from "../../util/JWKUtil.ts";
import { AbstractSignJWT } from "./AbstractSignJWT.ts";

export class SignFakeIdToken extends AbstractSignJWT {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims", "client_jwks", "id_token"] };
	static override post: EnvironmentRequirements = { required: ["id_token"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const claims = env.getObject("id_token_claims");
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
		const idTokenObj = env.getObject("id_token") as JsonObject;
		idTokenObj["value"] = jws;
		env.putObject("id_token", idTokenObj);
		this.logSuccess("Signed a 'fake' ID token using the client's keys", args("id_token", verifiableObj));
	}
}
