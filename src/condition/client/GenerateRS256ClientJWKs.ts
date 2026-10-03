import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { PreGeneratedJwks } from "../../util/PreGeneratedJwks.ts";
import { AbstractGenerateClientJWKs } from "./AbstractGenerateClientJWKs.ts";

export class GenerateRS256ClientJWKs extends AbstractGenerateClientJWKs {
	static override post: EnvironmentRequirements = { required: ["client_jwks", "client_public_jwks"] };

	override evaluate(env: Environment): Environment {
		// new RSAKey.Builder(...).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build()
		const key = PreGeneratedJwks.nextRsaKey(env, AbstractGenerateClientJWKs.DEFAULT_KEY_SIZE);
		key["use"] = "sig";
		key["alg"] = "RS256";
		return this.publishClientJWKs(env, key);
	}
}
