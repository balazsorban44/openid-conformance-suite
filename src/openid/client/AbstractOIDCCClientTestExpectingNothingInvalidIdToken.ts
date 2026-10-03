import { TestFailureException } from "../../framework/index.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export abstract class AbstractOIDCCClientTestExpectingNothingInvalidIdToken extends AbstractOIDCCClientTest {
	protected abstract getAuthorizationCodeGrantTypeErrorMessage(): string;
	protected abstract getHandleUserinfoEndpointRequestErrorMessage(): string;

	protected isInvalidSignature(): boolean {
		return false;
	}

	protected override async handleAuthorizationEndpointRequest(requestId: string): Promise<Response> {
		const returnValue = await super.handleAuthorizationEndpointRequest(requestId);
		if (this.isAuthorizationCodeRequestUnexpected()) {
			this.startWaitingForTimeout();
		}
		return returnValue;
	}

	protected isAuthorizationCodeRequestUnexpected(): boolean {
		return this.responseType.includesIdToken();
	}

	protected override async authorizationCodeGrantType(requestId: string): Promise<Response> {
		if (this.isAuthorizationCodeRequestUnexpected()) {
			throw new TestFailureException(this.getId(), this.getAuthorizationCodeGrantTypeErrorMessage());
		} else {
			this.startWaitingForTimeout();
		}
		return super.authorizationCodeGrantType(requestId);
	}

	protected override async handleUserinfoEndpointRequest(_requestId: string): Promise<Response> {
		if (this.isInvalidSignature()) {
			if (!this.responseType.includesIdToken()) {
				this.fireTestSkipped(
					"The client continued and called the userinfo endpoint after receiving an id token with an invalid signature from the token endpoint. This is acceptable as clients are not required to validate the signatures on id tokens received over a TLS protected connection.",
				);
			}
		}
		throw new TestFailureException(this.getId(), this.getHandleUserinfoEndpointRequestErrorMessage());
	}
}
