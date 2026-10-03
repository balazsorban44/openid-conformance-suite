import {
	isJsonPrimitive,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractVerifyJweEncryption } from "./AbstractVerifyJweEncryption.ts";

export class ValidateLogoutTokenFromBackchannelLogoutRequestEncryption extends AbstractVerifyJweEncryption {
	static override pre: EnvironmentRequirements = { required: ["backchannel_logout_request", "client_jwks"] };

	override evaluate(env: Environment): Environment {
		const clientJwks = env.getObject("client_jwks") as JsonObject;

		const tokenElement = env.getElementFromObject("backchannel_logout_request", "body_form_params.logout_token");
		if (tokenElement == null || !isJsonPrimitive(tokenElement)) {
			throw this.error("Couldn't find logout_token in backchannel_logout_request.body_form_params");
		}

		const idToken = OIDFJSON.getString(tokenElement);

		if (this.verifyJweEncryption(idToken, clientJwks, "logout_token")) {
			this.logSuccess("The client has a valid asymmetric key to decrypt the logout token");
		} else {
			this.logSuccess("The logout token is not encrypted using an asymmetric encryption algorithm");
		}

		return env;
	}
}
