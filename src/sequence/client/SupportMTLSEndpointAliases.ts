import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { AddMTLSEndpointAliasesToEnvironment } from "../../condition/client/AddMTLSEndpointAliasesToEnvironment.ts";

export class SupportMTLSEndpointAliases extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndContinueOnFailure(AddMTLSEndpointAliasesToEnvironment, ConditionResult.FAILURE, "RFC8705-5");
	}
}
