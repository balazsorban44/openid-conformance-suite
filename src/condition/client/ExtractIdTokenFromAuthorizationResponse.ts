import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractExtractJWT } from "../AbstractExtractJWT.ts";

export class ExtractIdTokenFromAuthorizationResponse extends AbstractExtractJWT {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };
	static override post: EnvironmentRequirements = { required: ["id_token"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const client = env.getObject("client");
		const clientJwks = env.getObject("client_jwks");
		return this.extractJWT(env, "authorization_endpoint_response", "id_token", "id_token", client, clientJwks);
	}
}
