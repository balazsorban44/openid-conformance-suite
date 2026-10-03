import { AbstractEnsureTokenEndPointAuthMethod } from "./AbstractEnsureTokenEndPointAuthMethod.ts";

export class EnsureTokenEndPointAuthMethodIsPrivateKeyJwt extends AbstractEnsureTokenEndPointAuthMethod {
	override expectedTokenEndPointAuthMethod(): string {
		return "private_key_jwt";
	}
}
