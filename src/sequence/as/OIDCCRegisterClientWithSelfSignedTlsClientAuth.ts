import { AbstractConditionSequence } from "../../framework/index.ts";
import { EnsureTokenEndPointAuthMethodIsSelfSignedTlsClientAuth } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsSelfSignedTlsClientAuth.ts";

export class OIDCCRegisterClientWithSelfSignedTlsClientAuth extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsSelfSignedTlsClientAuth);
	}
}
