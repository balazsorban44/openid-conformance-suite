import { EnsureTokenEndPointAuthMethodIsClientSecretBasic } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsClientSecretBasic.ts";
import { OIDCCRegisterClientWithClientSecret } from "./OIDCCRegisterClientWithClientSecret.ts";

export class OIDCCRegisterClientWithClientSecretBasic extends OIDCCRegisterClientWithClientSecret {
	override evaluate(): void {
		super.evaluate();
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsClientSecretBasic);
	}
}
