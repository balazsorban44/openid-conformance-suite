import { AbstractEnsureTokenEndPointAuthMethod } from "./AbstractEnsureTokenEndPointAuthMethod.ts";

export class EnsureTokenEndPointAuthMethodIsNone extends AbstractEnsureTokenEndPointAuthMethod {
	override expectedTokenEndPointAuthMethod(): string {
		return "none";
	}
}
