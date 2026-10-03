import { EnsureTokenEndPointAuthMethodIsClientSecretPost } from "../../condition/as/dynregistration/EnsureTokenEndPointAuthMethodIsClientSecretPost.ts";
import { OIDCCRegisterClientWithClientSecret } from "./OIDCCRegisterClientWithClientSecret.ts";

export class OIDCCRegisterClientWithClientSecretPost extends OIDCCRegisterClientWithClientSecret {
	override evaluate(): void {
		super.evaluate();
		this.callAndStopOnFailure(EnsureTokenEndPointAuthMethodIsClientSecretPost);
	}
}
