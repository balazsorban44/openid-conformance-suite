import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractJWEEncryptString } from "./AbstractJWEEncryptString.ts";

export class EncryptUserInfoResponse extends AbstractJWEEncryptString {
	static override pre: EnvironmentRequirements = { required: ["client"] };
	static override post: EnvironmentRequirements = { strings: ["encrypted_user_info_endpoint_response"] };

	/**
	 * Also requires, either signed_user_info_endpoint_response or user_info_endpoint_response
	 * @param env
	 * @return
	 */
	override async evaluate(env: Environment): Promise<Environment> {
		let userinfoResponse = env.getString("signed_user_info_endpoint_response");
		if (userinfoResponse == null) {
			const unsignedUserinfo = env.getObject("user_info_endpoint_response");
			userinfoResponse = JSON.stringify(unsignedUserinfo);
		}
		const alg = env.getString("client", "userinfo_encrypted_response_alg");
		const enc = env.getString("client", "userinfo_encrypted_response_enc");
		const clientSecret = env.getString("client", "client_secret");
		//client jwks may be null
		const clientJwksElement = env.getElementFromObject("client", "jwks");
		let clientJwks: JsonObject | null = null;
		if (clientJwksElement != null) {
			clientJwks = clientJwksElement as JsonObject;
		}

		const encryptedResponse = await this.encrypt(
			"client",
			userinfoResponse,
			clientSecret,
			clientJwks,
			alg,
			enc,
			"userinfo_encrypted_response_alg",
			"userinfo_encrypted_response_enc",
		);

		this.logSuccess(
			"Encrypted userinfo response",
			args(
				"userinfo",
				encryptedResponse,
				"userinfo_encrypted_response_alg",
				alg,
				"userinfo_encrypted_response_enc",
				enc,
			),
		);
		env.putString("encrypted_user_info_endpoint_response", encryptedResponse);
		return env;
	}
}
