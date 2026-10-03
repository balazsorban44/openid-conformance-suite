import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckErrorDescriptionContainsCRLFTAB } from "./AbstractCheckErrorDescriptionContainsCRLFTAB.ts";

export class CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB extends AbstractCheckErrorDescriptionContainsCRLFTAB {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		return this.checkExistCRLFTAB(env, "token_endpoint_response");
	}
}
