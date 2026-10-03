import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 * request_object_encryption_enc
 * OPTIONAL. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting
 * Request Objects sent to the OP. If request_object_encryption_alg is specified, the default
 * for this value is A128CBC-HS256. When request_object_encryption_enc is included,
 * request_object_encryption_alg MUST also be provided.
 *
 */
export class EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		const enc = this.getRequestObjectEncryptionEnc();
		const alg = this.getRequestObjectEncryptionAlg();
		if (enc != null && alg == null) {
			throw this.error(
				"When request_object_encryption_enc is included, request_object_encryption_alg MUST " + "also be provided.",
				args("request_object_encryption_alg", alg, "request_object_encryption_enc", enc),
			);
		}
		if (enc == null) {
			this.logSuccess("request_object_encryption_enc is not set");
			return env;
		}
		this.logSuccess(
			"request_object_encryption_alg is set",
			args("request_object_encryption_alg", alg, "request_object_encryption_enc", enc),
		);
		return env;
	}
}
