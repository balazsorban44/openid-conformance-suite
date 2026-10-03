import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractVerifyScopesReturnedInClaims } from "./AbstractVerifyScopesReturnedInClaims.ts";

export class VerifyScopesReturnedInAuthorizationEndpointIdToken extends AbstractVerifyScopesReturnedInClaims {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_id_token", "authorization_endpoint_request"],
	};

	override evaluate(env: Environment): Environment {
		const claims = env.getElementFromObject("authorization_endpoint_id_token", "claims");
		return this.verifyScopesInClaims(env, claims, "authorization_endpoint_id_token");
	}
}
