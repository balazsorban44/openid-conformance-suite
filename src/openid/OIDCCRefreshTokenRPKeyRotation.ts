import { AddJwksUriToDynamicRegistrationRequest } from "../condition/client/AddJwksUriToDynamicRegistrationRequest.ts";
import { AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess } from "../condition/client/AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess.ts";
import { AddPublicJwksToDynamicRegistrationRequest } from "../condition/client/AddPublicJwksToDynamicRegistrationRequest.ts";
import { AddRefreshTokenGrantTypeToDynamicRegistrationRequest } from "../condition/client/AddRefreshTokenGrantTypeToDynamicRegistrationRequest.ts";
import { CreateJwksUri } from "../condition/client/CreateJwksUri.ts";
import { EnsureRefreshTokenContainsAllowedCharactersOnly } from "../condition/client/EnsureRefreshTokenContainsAllowedCharactersOnly.ts";
import { EnsureServerConfigurationSupportsRefreshToken } from "../condition/client/EnsureServerConfigurationSupportsRefreshToken.ts";
import { ExtractRefreshTokenFromTokenResponse } from "../condition/client/ExtractRefreshTokenFromTokenResponse.ts";
import { GenerateRS256ClientJWKs } from "../condition/client/GenerateRS256ClientJWKs.ts";
import { GenerateRS256ClientJWKsWithKeyID } from "../condition/client/GenerateRS256ClientJWKsWithKeyID.ts";
import { SetScopeInClientConfigurationToOpenIdOfflineAccess } from "../condition/client/SetScopeInClientConfigurationToOpenIdOfflineAccess.ts";
import { WaitForJWKSRefreshDelay } from "../condition/client/WaitForJWKSRefreshDelay.ts";
import { OIDCCCreateDynamicClientRegistrationRequest } from "../sequence/client/OIDCCCreateDynamicClientRegistrationRequest.ts";
import { RefreshTokenRequestSteps } from "../sequence/client/RefreshTokenRequestSteps.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import {
	ConditionResult,
	jsonResponse,
	TestFailureException,
	type ConditionSequence,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Rotation_RP_Sig
export class OIDCCRefreshTokenRPKeyRotation extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-refresh-token-rp-key-rotation",
		displayName:
			"OIDCC: Use a refresh token with private_key_jwt client authentication to ensure the server can handle RP key rotation",
		summary:
			"This test obtains a refresh token (by registering the client for the refresh_token grant and including scope=offline_access in the authorization endpoint request). Once it has obtained the refresh token it rotates the keys (by placing a new RP key with a new kid into the RP's jwks_uri), waits 60 seconds then tries to use the refresh token with a client assertion containing the new kid. Support for private_key_jwt client authentication, scope=offline_access and refresh tokens are not a requirement of the specification but are required to certify for the 'dynamic' profile.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [
			{ parameter: ResponseType, values: ["id_token", "id_token token"] },
			{ parameter: ClientRegistration, values: ["static_client"] },
			{
				parameter: ClientAuthType,
				values: ["none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "mtls"],
			}, // this test relies on sending a client assertion containing the new kid so private_key_jwt is required
		],
	};

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await this.callAndStopOnFailure(CreateJwksUri);
		await this.call(
			new OIDCCCreateDynamicClientRegistrationRequest(this.responseType)
				.replace(GenerateRS256ClientJWKs, this.condition(GenerateRS256ClientJWKsWithKeyID))
				.replace(AddPublicJwksToDynamicRegistrationRequest, this.condition(AddJwksUriToDynamicRegistrationRequest)),
		);

		await this.callAndStopOnFailure(AddRefreshTokenGrantTypeToDynamicRegistrationRequest);

		this.expose("client_name", this.env.getString("dynamic_registration_request", "client_name"));
	}

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === "client1_jwks") {
			return this.handleJwksRequest();
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	private handleJwksRequest(): Response {
		const clientPublicJwks = this.env.getObject("client_public_jwks");
		if (clientPublicJwks == null) {
			throw new TestFailureException(
				this.getId(),
				"jwks endpoint called before key exists - please wait for test to initialise before calling client jwks endpoint",
			);
		}
		return jsonResponse(clientPublicJwks, 200);
	}

	protected override async completeClientConfiguration(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdOfflineAccess);

		if (this.profileCompleteClientConfiguration != null) {
			await this.call(this.sequence(this.profileCompleteClientConfiguration));
		}
	}

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.then(
				this.condition(AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess).requirement(
					"OIDCC-11",
				),
			);
	}

	protected override async performPostAuthorizationFlow(): Promise<void> {
		await this.createAuthorizationCodeRequest();

		// Store the original access token and ID token separately (see RefreshTokenRequestSteps)
		this.env.mapKey("access_token", "first_access_token");
		this.env.mapKey("id_token", "first_id_token");

		await this.requestAuthorizationCode();

		// Set up the mappings for the refreshed access and ID tokens
		this.env.mapKey("access_token", "second_access_token");
		this.env.mapKey("id_token", "second_id_token");

		this.eventLog.startBlock("Cycling keys in RP jwks_uri");
		await this.callAndStopOnFailure(GenerateRS256ClientJWKsWithKeyID);
		this.eventLog.endBlock();

		this.eventLog.startBlock("Waiting, so that any DoS limits on retrieving the jwks_uri too often are not triggered");
		// the python test does not have this wait, which causes the python test to fail against node oidc provider and Authlete
		// as it hits limits on how frequently jwks_uri is retrieved - the sleep avoids this.
		//
		// The sleep may be decreased via the 'jwks_refresh_delay' server configuration property.
		await this.callAndStopOnFailure(WaitForJWKSRefreshDelay);
		this.eventLog.endBlock();

		await this.sendRefreshTokenRequestAndCheckIdTokenClaims();

		await this.requestProtectedResource();

		await this.onPostAuthorizationFlowComplete();
	}

	protected async sendRefreshTokenRequestAndCheckIdTokenClaims(): Promise<void> {
		await this.callAndStopOnFailure(ExtractRefreshTokenFromTokenResponse);
		await this.callAndContinueOnFailure(
			EnsureServerConfigurationSupportsRefreshToken,
			ConditionResult.WARNING,
			"OIDCD-3",
		);
		await this.callAndContinueOnFailure(
			EnsureRefreshTokenContainsAllowedCharactersOnly,
			ConditionResult.FAILURE,
			"RFC6749-A.17",
		);
		await this.call(new RefreshTokenRequestSteps(false, this.addTokenEndpointClientAuthentication));
	}
}
