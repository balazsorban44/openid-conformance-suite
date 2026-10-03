import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractJWEEncryptString } from "./AbstractJWEEncryptString.ts";

export class EncryptIdToken extends AbstractJWEEncryptString {
	static override pre: EnvironmentRequirements = { strings: ["id_token"], required: ["client"] };
	static override post: EnvironmentRequirements = { strings: ["id_token"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const idToken = env.getString("id_token") as string;
		const alg = env.getString("client", "id_token_encrypted_response_alg");
		const enc = env.getString("client", "id_token_encrypted_response_enc");
		const clientSecret = env.getString("client", "client_secret");
		//client jwks may be null
		const clientJwksElement = env.getElementFromObject("client", "jwks");
		let clientJwks: JsonObject | null = null;
		if (clientJwksElement != null) {
			clientJwks = clientJwksElement as JsonObject;
		}

		const encryptedIdToken = await this.encrypt(
			"client",
			idToken,
			clientSecret,
			clientJwks,
			alg,
			enc,
			"id_token_encrypted_response_alg",
			"id_token_encrypted_response_enc",
		);

		this.log(
			"Encrypted the id token",
			args(
				"id_token",
				encryptedIdToken,
				"id_token_encrypted_response_alg",
				alg,
				"id_token_encrypted_response_enc",
				enc,
			),
		);
		env.putString("id_token", encryptedIdToken);
		return env;
	}
}
