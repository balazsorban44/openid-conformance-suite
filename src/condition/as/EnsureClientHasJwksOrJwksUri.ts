import {
	AbstractCondition,
	args,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class EnsureClientHasJwksOrJwksUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;

		if (!has(client, "jwks") && !has(client, "jwks_uri")) {
			throw this.error(
				"Client must have either jwks or jwks_uri set. This is typically required " +
					"when client authentication type is private_key_jwt " +
					" or self_signed_tls_client_auth, " +
					"or when an asymmetric algorithm is used for request_object_signing_alg, " +
					"id_token_encrypted_response_alg or userinfo_encrypted_response_alg.",
				args("client", client),
			);
		}
		this.logSuccess("Client has jwks or jwks_uri", args("client", client));
		return env;
	}
}
