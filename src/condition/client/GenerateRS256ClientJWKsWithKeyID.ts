import { calculateJwkThumbprint, errors } from "jose";
import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { PreGeneratedJwks } from "../../util/PreGeneratedJwks.ts";
import { AbstractGenerateClientJWKs } from "./AbstractGenerateClientJWKs.ts";

export class GenerateRS256ClientJWKsWithKeyID extends AbstractGenerateClientJWKs {
	static override post: EnvironmentRequirements = { required: ["client_jwks", "client_public_jwks"] };

	override async evaluate(env: Environment): Promise<Environment> {
		try {
			// new RSAKey.Builder(...).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).keyIDFromThumbprint().build()
			const key = PreGeneratedJwks.nextRsaKey(env, AbstractGenerateClientJWKs.DEFAULT_KEY_SIZE);
			key["use"] = "sig";
			key["alg"] = "RS256";
			key["kid"] = await calculateJwkThumbprint(key, "sha256");
			return this.publishClientJWKs(env, key);
		} catch (e) {
			if (e instanceof errors.JOSEError) {
				throw this.error("Failed to build client signing key", e);
			}
			throw e;
		}
	}
}
