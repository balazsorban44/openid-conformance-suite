import { EnsureTokenEndPointAuthMethodIsClientSecretJwt } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsClientSecretJwt.ts";
import { OIDCCRegisterClientWithClientSecret } from "./OIDCCRegisterClientWithClientSecret.ts";

export class OIDCCRegisterClientWithClientSecretJwt extends OIDCCRegisterClientWithClientSecret {
	override evaluate(): void {
		super.evaluate();
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsClientSecretJwt);
	}
}
