import { AbstractConditionSequence } from "../../framework/index.ts";
import { EnsureTokenEndPointAuthMethodIsPrivateKeyJwt } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsPrivateKeyJwt.ts";

export class OIDCCRegisterClientWithPrivateKeyJwt extends AbstractConditionSequence {
	override evaluate(): void {
		//AbstractOIDCCClientTest will perform jwks validation
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsPrivateKeyJwt);
	}
}
