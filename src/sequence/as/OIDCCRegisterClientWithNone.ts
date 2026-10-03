import { AbstractConditionSequence } from "../../framework/index.ts";
import { EnsureTokenEndPointAuthMethodIsNone } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsNone.ts";

export class OIDCCRegisterClientWithNone extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsNone);
	}
}
