import { AbstractEnsureTokenEndPointAuthMethod } from "./AbstractEnsureTokenEndPointAuthMethod.ts";

export class EnsureTokenEndPointAuthMethodIsSelfSignedTlsClientAuth extends AbstractEnsureTokenEndPointAuthMethod {
	override expectedTokenEndPointAuthMethod(): string {
		return "self_signed_tls_client_auth";
	}
}
