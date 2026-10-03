import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractVerifyScopesReturnedInClaims } from "./AbstractVerifyScopesReturnedInClaims.ts";

export class VerifyScopesReturnedInUserInfoClaims extends AbstractVerifyScopesReturnedInClaims {
	static override pre: EnvironmentRequirements = { required: ["userinfo", "authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const claims = env.getObject("userinfo");
		return this.verifyScopesInClaims(env, claims, "userinfo");
	}
}
