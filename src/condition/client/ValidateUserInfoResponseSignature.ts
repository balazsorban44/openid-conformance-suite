import { type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractVerifyJwsSignature } from "./AbstractVerifyJwsSignature.ts";

const USERINFO_ENDPOINT_RESPONSE = "userinfo_endpoint_response_full";

export class ValidateUserInfoResponseSignature extends AbstractVerifyJwsSignature {
	static override pre: EnvironmentRequirements = { required: ["server_jwks", USERINFO_ENDPOINT_RESPONSE] };

	override async evaluate(env: Environment): Promise<Environment> {
		const userInfoStr = env.getString(USERINFO_ENDPOINT_RESPONSE, "body") as string;

		const serverJwks = env.getObject("server_jwks") as JsonObject; // to validate the signature

		await this.verifyJwsSignature(userInfoStr, serverJwks, USERINFO_ENDPOINT_RESPONSE, false, "server");

		return env;
	}
}
