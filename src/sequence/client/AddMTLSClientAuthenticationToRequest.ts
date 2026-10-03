import { AbstractConditionSequence } from "../../framework/index.ts";
import { AddClientIdToRequest } from "../../condition/client/AddClientIdToRequest.ts";

export class AddMTLSClientAuthenticationToRequest extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(AddClientIdToRequest);
	}
}
