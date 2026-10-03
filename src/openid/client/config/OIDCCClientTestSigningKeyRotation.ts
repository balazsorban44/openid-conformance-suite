import { TestFailureException, type PublishTestModule } from "../../../framework/index.ts";
import { ClientRegistration } from "../../../variant/ClientRegistration.ts";
import { ResponseType } from "../../../variant/ResponseType.ts";
import { AbstractOIDCCClientTest } from "../AbstractOIDCCClientTest.ts";

export class OIDCCClientTestSigningKeyRotation extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-signing-key-rotation",
		displayName: "OIDCC: Relying party signing key rotation test",
		summary:
			"The client is expected to request an ID token and verify its signature by" +
			" fetching keys from the jwks endpoint. " +
			" Then make a new authentication request and retrieve another ID Token and verify its signature." +
			" Keys will be rotated after the first ID token is issued so the client needs to refetch the jwks to validate " +
			"the second ID token." +
			"Corresponds to rp-key-rotation-op-sign-key test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected receivedSecondJwksRequest = false;
	protected receivedSecondAuthorizationRequest = false;
	protected receivedSecondTokenRequest = false;
	protected receivedSecondUserinfoRequest = false;

	protected override async finishTestIfAllRequestsAreReceived(): Promise<boolean> {
		let fireTestFinishedCalled = false;
		switch (this.responseType) {
			case ResponseType.CODE:
				if (this.receivedSecondUserinfoRequest && this.receivedSecondJwksRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.CODE_ID_TOKEN:
				if (this.receivedSecondUserinfoRequest && this.receivedSecondJwksRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.ID_TOKEN:
				if (this.receivedSecondAuthorizationRequest && this.receivedSecondJwksRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.CODE_TOKEN:
				if (this.receivedSecondUserinfoRequest && this.receivedSecondJwksRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.CODE_ID_TOKEN_TOKEN:
				if (this.receivedSecondUserinfoRequest && this.receivedSecondJwksRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
			case ResponseType.ID_TOKEN_TOKEN:
				if (this.receivedSecondUserinfoRequest && this.receivedSecondJwksRequest) {
					await this.fireTestFinished();
					fireTestFinishedCalled = true;
				}
				break;
		}
		return fireTestFinishedCalled;
	}

	protected override async handleClientRequestForPath(
		requestId: string,
		path: string,
		_servletResponse: unknown,
	): Promise<Response> {
		if (path === "authorize") {
			if (this.receivedAuthorizationRequest) {
				this.env.removeObject("client_authentication");
				this.receivedSecondAuthorizationRequest = true;
				await super.configureServerJWKS();
			} else {
				this.receivedAuthorizationRequest = true;
			}
			return this.handleAuthorizationEndpointRequest(requestId);
		} else if (path === "token") {
			if (this.receivedTokenRequest) {
				this.receivedSecondTokenRequest = true;
			} else {
				this.receivedTokenRequest = true;
			}
			return this.handleTokenEndpointRequest(requestId);
		} else if (path === this.getJwksPath()) {
			if (this.receivedJwksRequest) {
				this.receivedSecondJwksRequest = true;
			} else {
				this.receivedJwksRequest = true;
			}
			return this.handleJwksEndpointRequest();
		} else if (path === "userinfo") {
			if (this.receivedUserinfoRequest) {
				this.receivedSecondUserinfoRequest = true;
			} else {
				this.receivedUserinfoRequest = true;
			}
			return this.handleUserinfoEndpointRequest(requestId);
		} else if (path === "register" && this.clientRegistrationType === ClientRegistration.DYNAMIC_CLIENT) {
			this.receivedRegistrationRequest = true;
			return this.handleRegistrationEndpointRequest(requestId);
		} else if (path === ".well-known/openid-configuration") {
			this.receivedDiscoveryRequest = true;
			return this.handleDiscoveryEndpointRequest();
		} else {
			throw new TestFailureException(this.getId(), "Got unexpected HTTP call to " + path);
		}
	}

	protected override async signIdToken(): Promise<void> {
		await super.signIdToken();
	}

	protected override getAuthorizationEndpointBlockText(): string {
		if (this.receivedSecondAuthorizationRequest) {
			return "Second Authorization Request";
		}
		return super.getAuthorizationEndpointBlockText();
	}
}
