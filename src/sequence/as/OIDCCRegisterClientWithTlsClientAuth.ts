import { AbstractConditionSequence } from "../../framework/index.ts";
import { EnsureTokenEndPointAuthMethodIsTlsClientAuth } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsTlsClientAuth.ts";

export class OIDCCRegisterClientWithTlsClientAuth extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsTlsClientAuth);
	}
}
