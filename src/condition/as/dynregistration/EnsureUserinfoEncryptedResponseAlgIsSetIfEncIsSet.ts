import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 * userinfo_encrypted_response_enc
 * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses.
 * If userinfo_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
 * When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
 *
 */
export class EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		const enc = this.getUserinfoEncryptedResponseEnc();
		const alg = this.getUserinfoEncryptedResponseAlg();
		if (enc != null && alg == null) {
			throw this.error(
				"When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST " + "also be provided.",
				args("userinfo_encrypted_response_alg", alg, "userinfo_encrypted_response_enc", enc),
			);
		}
		if (enc == null) {
			this.logSuccess("userinfo_encrypted_response_enc is not set");
			return env;
		}
		this.logSuccess(
			"userinfo_encrypted_response_alg is set",
			args("userinfo_encrypted_response_alg", alg, "userinfo_encrypted_response_enc", enc),
		);
		return env;
	}
}
