import { AbstractVerifyUserInfoAndIdTokenSameSub } from "./AbstractVerifyUserInfoAndIdTokenSameSub.ts";

export class VerifyUserInfoAndIdTokenInTokenEndpointSameSub extends AbstractVerifyUserInfoAndIdTokenSameSub {
	protected override getIdTokenKey(): string {
		return "token_endpoint_id_token";
	}
}
