import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 * id_token_encrypted_response_enc
 * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client.
 * If id_token_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
 * When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
 *
 */
export class EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		const enc = this.getIdTokenEncryptedResponseEnc();
		const alg = this.getIdTokenEncryptedResponseAlg();
		if (enc != null && alg == null) {
			throw this.error(
				"When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST " + "also be provided.",
				args("id_token_encrypted_response_alg", alg, "id_token_encrypted_response_enc", enc),
			);
		}
		if (enc == null) {
			this.logSuccess("id_token_encrypted_response_enc is not set");
			return env;
		}
		this.logSuccess(
			"id_token_encrypted_response_alg is set",
			args("id_token_encrypted_response_alg", alg, "id_token_encrypted_response_enc", enc),
		);
		return env;
	}
}
