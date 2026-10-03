import { AbstractConditionSequence } from "../../framework/index.ts";
import { AbstractOIDCCClientTest } from "../../openid/client/AbstractOIDCCClientTest.ts";
import { EnsureTokenEndPointAuthMethodIsPrivateKeyJwt } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsPrivateKeyJwt.ts";

export class OIDCCRegisterClientWithPrivateKeyJwt extends AbstractConditionSequence {
	override evaluate(): void {
		//AbstractOIDCCClientTest will perform jwks validation
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsPrivateKeyJwt);
	}
}
