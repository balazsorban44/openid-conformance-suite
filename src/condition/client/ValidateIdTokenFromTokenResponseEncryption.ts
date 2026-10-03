import {
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractVerifyJweEncryption } from "./AbstractVerifyJweEncryption.ts";

export class ValidateIdTokenFromTokenResponseEncryption extends AbstractVerifyJweEncryption {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response", "client_jwks"] };

	override evaluate(env: Environment): Environment {
		const clientJwks = env.getObject("client_jwks") as JsonObject;

		const tokenElement = env.getElementFromObject("token_endpoint_response", "id_token");
		if (tokenElement == null || !isJsonPrimitive(tokenElement)) {
			throw this.error("Couldn't find id_token in token_endpoint_response");
		}

		const idToken = OIDFJSON.getString(tokenElement);

		if (this.verifyJweEncryption(idToken, clientJwks, "id_token")) {
			this.logSuccess("The client has a valid asymmetric key to decrypt the id_token");
		} else {
			this.logSuccess("The id_token is not encrypted using an asymmetric encryption algorithm");
		}

		return env;
	}
}
