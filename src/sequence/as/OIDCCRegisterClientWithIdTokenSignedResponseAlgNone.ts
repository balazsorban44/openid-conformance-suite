import { AbstractConditionSequence } from "../../framework/index.ts";
import { SetClientGrantTypesToAuthorizationCodeOnly } from "../../condition/as/dynregistration/SetClientGrantTypesToAuthorizationCodeOnly.ts";
import { SetClientIdTokenSignedResponseAlgToNone } from "../../condition/as/dynregistration/SetClientIdTokenSignedResponseAlgToNone.ts";

export class OIDCCRegisterClientWithIdTokenSignedResponseAlgNone extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(SetClientIdTokenSignedResponseAlgToNone);
		this.callAndStopOnFailure(SetClientGrantTypesToAuthorizationCodeOnly);
	}
}
