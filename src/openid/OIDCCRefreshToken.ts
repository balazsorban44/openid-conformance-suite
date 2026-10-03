import { AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess } from "../condition/client/AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess.ts";
import { AddRefreshTokenGrantTypeToDynamicRegistrationRequest } from "../condition/client/AddRefreshTokenGrantTypeToDynamicRegistrationRequest.ts";
import { CreateRandomNonceValue } from "../condition/client/CreateRandomNonceValue.ts";
import { EnsureRefreshTokenContainsAllowedCharactersOnly } from "../condition/client/EnsureRefreshTokenContainsAllowedCharactersOnly.ts";
import { EnsureServerConfigurationDoesNotSupportRefreshToken } from "../condition/client/EnsureServerConfigurationDoesNotSupportRefreshToken.ts";
import { EnsureServerConfigurationSupportsRefreshToken } from "../condition/client/EnsureServerConfigurationSupportsRefreshToken.ts";
import { ExtractRefreshTokenFromTokenResponse } from "../condition/client/ExtractRefreshTokenFromTokenResponse.ts";
import { SetScopeInClientConfigurationToOpenId } from "../condition/client/SetScopeInClientConfigurationToOpenId.ts";
import { SetScopeInClientConfigurationToOpenIdOfflineAccess } from "../condition/client/SetScopeInClientConfigurationToOpenIdOfflineAccess.ts";
import { SetScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess } from "../condition/client/SetScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess.ts";
import { RefreshTokenRequestExpectingErrorSteps } from "../sequence/client/RefreshTokenRequestExpectingErrorSteps.ts";
import { RefreshTokenRequestSteps } from "../sequence/client/RefreshTokenRequestSteps.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import {
	Command,
	ConditionResult,
	type ConditionSequence,
	type ConditionSequenceClass,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCMultipleClient } from "./AbstractOIDCCMultipleClient.ts";

export class OIDCCRefreshToken extends AbstractOIDCCMultipleClient {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-refresh-token",
		displayName: "OIDCC: test refresh token behaviours",
		summary:
			"This test obtains refresh tokens and performs various checks, including checking that the refresh token works and is correctly bound to the client. Support for refresh tokens is optional and the test will be skipped if the token endpoint response does not return refresh tokens. scope=offline_access will be included in the authorization endpoint request if the server's discovery document indicates support for this scope.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token", "id_token token"] }],
	};

	protected override async completeClientConfiguration(): Promise<void> {
		if (this.serverSupportsDiscovery()) {
			await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenId);
			await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess);
		} else {
			// no discovery, so no idea if server supports offline_access scope or not - request it anyway, servers
			// 'should' ignore unknown scope values
			await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdOfflineAccess);
		}

		if (this.profileCompleteClientConfiguration != null) {
			await this.call(this.sequence(this.profileCompleteClientConfiguration));
		}
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();

		await this.callAndStopOnFailure(AddRefreshTokenGrantTypeToDynamicRegistrationRequest);
	}

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		const cmd = new Command();
		if (this.isSecondClient()) {
			cmd.putInteger("requested_nonce_length", 43);
		} else {
			cmd.removeNativeValue("requested_nonce_length");
		}

		return super
			.createAuthorizationRequestSequence()
			.insertBefore(CreateRandomNonceValue, cmd)
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

		await this.sendRefreshTokenRequestAndCheckIdTokenClaims();

		await this.requestProtectedResource();

		await this.onPostAuthorizationFlowComplete();
	}

	protected async sendRefreshTokenRequestAndCheckIdTokenClaims(): Promise<void> {
		await this.callAndContinueOnFailure(ExtractRefreshTokenFromTokenResponse, ConditionResult.INFO);
		//stop if no refresh token is returned
		if (!this.env.getString("refresh_token")) {
			await this.callAndContinueOnFailure(
				EnsureServerConfigurationDoesNotSupportRefreshToken,
				ConditionResult.WARNING,
				"OIDCD-3",
			);
			// This throws an exception: the test will stop here
			this.fireTestSkipped("Refresh tokens cannot be tested. No refresh token was issued.");
		}
		if (this.serverSupportsDiscovery()) {
			await this.callAndContinueOnFailure(
				EnsureServerConfigurationSupportsRefreshToken,
				ConditionResult.WARNING,
				"OIDCD-3",
			);
		}
		await this.callAndContinueOnFailure(
			EnsureRefreshTokenContainsAllowedCharactersOnly,
			ConditionResult.FAILURE,
			"RFC6749-A.17",
		);
		await this.call(new RefreshTokenRequestSteps(this.isSecondClient(), this.addTokenEndpointClientAuthentication));
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		if (!this.isSecondClient()) {
			//remove refresh token from 1st client
			this.env.removeNativeValue("refresh_token");
			// Remove token mappings
			// (This must be done before restarting the authorization flow, because
			// handleSuccessfulAuthorizationEndpointResponse extracts an id token)
			this.env.unmapKey("access_token");
			this.env.unmapKey("id_token");
		}

		await super.onPostAuthorizationFlowComplete();
	}

	protected override async performSecondClientTests(): Promise<void> {
		// try client 2's refresh_token with client 1
		this.unmapClient();
		this.eventLog.startBlock("Attempting to use refresh_token issued to client 2 with client 1");
		await this.call(
			new RefreshTokenRequestExpectingErrorSteps(
				this.isSecondClient(),
				this.addTokenEndpointClientAuthentication as ConditionSequenceClass,
			),
		);
		this.eventLog.endBlock();
	}
}
