import { AbstractEnsureTokenEndPointAuthMethod } from "./AbstractEnsureTokenEndPointAuthMethod.ts";

export class EnsureTokenEndPointAuthMethodIsClientSecretBasic extends AbstractEnsureTokenEndPointAuthMethod {
	override expectedTokenEndPointAuthMethod(): string {
		return "client_secret_basic";
	}
}
