import { AbstractConditionSequence } from "../../framework/index.ts";
import { OIDCCCreateClientSecretForDynamicClient } from "../../condition/as/dynregistration/OIDCCCreateClientSecretForDynamicClient.ts";

export class OIDCCRegisterClientWithClientSecret extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(OIDCCCreateClientSecretForDynamicClient);
	}
}
