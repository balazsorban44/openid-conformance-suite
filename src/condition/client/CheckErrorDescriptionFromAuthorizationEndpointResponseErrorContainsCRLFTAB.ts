import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckErrorDescriptionContainsCRLFTAB } from "./AbstractCheckErrorDescriptionContainsCRLFTAB.ts";

export class CheckErrorDescriptionFromAuthorizationEndpointResponseErrorContainsCRLFTAB extends AbstractCheckErrorDescriptionContainsCRLFTAB {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		return this.checkExistCRLFTAB(env, "authorization_endpoint_response");
	}
}
