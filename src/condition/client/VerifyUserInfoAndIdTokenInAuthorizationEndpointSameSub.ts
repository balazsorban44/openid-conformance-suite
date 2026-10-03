import { AbstractVerifyUserInfoAndIdTokenSameSub } from "./AbstractVerifyUserInfoAndIdTokenSameSub.ts";

export class VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub extends AbstractVerifyUserInfoAndIdTokenSameSub {
	protected override getIdTokenKey(): string {
		return "authorization_endpoint_id_token";
	}
}
