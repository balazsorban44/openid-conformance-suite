import type { Environment, EnvironmentRequirements, JsonObject } from "../../framework/index.ts";
import { AbstractVerifyJwsSignature } from "../client/AbstractVerifyJwsSignature.ts";

export class ValidateClientAssertionSignature extends AbstractVerifyJwsSignature {
	static override pre: EnvironmentRequirements = { required: ["client", "client_assertion"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const clientAssertionString = env.getString("client_assertion", "value") as string;
		const client = env.getObject("client") as JsonObject;
		const clientJWKS = client["jwks"] as JsonObject;
		await this.verifyJwsSignature(clientAssertionString, clientJWKS, "client_assertion", true, "client");

		return env;
	}
}
