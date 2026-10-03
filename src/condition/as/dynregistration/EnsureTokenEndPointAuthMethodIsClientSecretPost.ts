import { AbstractEnsureTokenEndPointAuthMethod } from "./AbstractEnsureTokenEndPointAuthMethod.ts";

export class EnsureTokenEndPointAuthMethodIsClientSecretPost extends AbstractEnsureTokenEndPointAuthMethod {
	override expectedTokenEndPointAuthMethod(): string {
		return "client_secret_post";
	}
}
