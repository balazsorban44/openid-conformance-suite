import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { AbstractJWEEncryptString } from "../AbstractJWEEncryptString.ts";

export class EncryptLogoutToken extends AbstractJWEEncryptString {
	static override pre: EnvironmentRequirements = { strings: ["logout_token"], required: ["client"] };
	static override post: EnvironmentRequirements = { strings: ["logout_token"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const token = env.getString("logout_token") as string;
		const alg = env.getString("client", "id_token_encrypted_response_alg");
		const enc = env.getString("client", "id_token_encrypted_response_enc");
		const clientSecret = env.getString("client", "client_secret");
		//client jwks may be null
		const clientJwksElement = env.getElementFromObject("client", "jwks");
		let clientJwks: JsonObject | null = null;
		if (clientJwksElement != null) {
			clientJwks = clientJwksElement as JsonObject;
		}

		const encryptedToken = await this.encrypt(
			"client",
			token,
			clientSecret,
			clientJwks,
			alg,
			enc,
			"id_token_encrypted_response_alg",
			"id_token_encrypted_response_enc",
		);

		this.logSuccess(
			"Encrypted the logout token",
			args(
				"logout_token",
				encryptedToken,
				"id_token_encrypted_response_alg",
				alg,
				"id_token_encrypted_response_enc",
				enc,
			),
		);
		env.putString("logout_token", encryptedToken);
		return env;
	}
}
