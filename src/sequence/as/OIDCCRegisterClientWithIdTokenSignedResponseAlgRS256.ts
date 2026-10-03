import { AbstractConditionSequence } from "../../framework/index.ts";
import { SetClientIdTokenSignedResponseAlgToRS256 } from "../../condition/as/dynregistration/SetClientIdTokenSignedResponseAlgToRS256.ts";

export class OIDCCRegisterClientWithIdTokenSignedResponseAlgRS256 extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(SetClientIdTokenSignedResponseAlgToRS256);
	}
}
