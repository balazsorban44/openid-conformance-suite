import { type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractVerifyJwsSignature } from "./AbstractVerifyJwsSignature.ts";

export class ValidateLogoutTokenSignature extends AbstractVerifyJwsSignature {
	static override pre: EnvironmentRequirements = { required: ["logout_token", "server_jwks"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const idToken = env.getString("logout_token", "value") as string;
		const serverJwks = env.getObject("server_jwks") as JsonObject; // to validate the signature

		await this.verifyJwsSignature(idToken, serverJwks, "logout_token", false, "server");

		return env;
	}
}
