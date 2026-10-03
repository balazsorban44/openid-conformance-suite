import { CallTokenEndpointAndReturnFullResponse } from "../condition/client/CallTokenEndpointAndReturnFullResponse.ts";
import { CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB } from "../condition/client/CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB.ts";
import { CheckErrorFromTokenEndpointResponseErrorInvalidClient } from "../condition/client/CheckErrorFromTokenEndpointResponseErrorInvalidClient.ts";
import { CheckForAccessTokenValue } from "../condition/client/CheckForAccessTokenValue.ts";
import { CheckForRefreshTokenValue } from "../condition/client/CheckForRefreshTokenValue.ts";
import { CheckIfTokenEndpointResponseError } from "../condition/client/CheckIfTokenEndpointResponseError.ts";
import { CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError } from "../condition/client/CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError.ts";
import { CheckTokenEndpointReturnedJsonContentType } from "../condition/client/CheckTokenEndpointReturnedJsonContentType.ts";
import { CreateClientAuthenticationAssertionClaims } from "../condition/client/CreateClientAuthenticationAssertionClaims.ts";
import { CreateTokenEndpointRequestForAuthorizationCodeGrant } from "../condition/client/CreateTokenEndpointRequestForAuthorizationCodeGrant.ts";
import { ExtractAccessTokenFromTokenResponse } from "../condition/client/ExtractAccessTokenFromTokenResponse.ts";
import { ExtractExpiresInFromTokenEndpointResponse } from "../condition/client/ExtractExpiresInFromTokenEndpointResponse.ts";
import { ExtractIdTokenFromTokenResponse } from "../condition/client/ExtractIdTokenFromTokenResponse.ts";
import { UpdateClientAuthenticationAssertionClaimsWithISSAud } from "../condition/client/UpdateClientAuthenticationAssertionClaimsWithISSAud.ts";
import { ValidateErrorDescriptionFromTokenEndpointResponseError } from "../condition/client/ValidateErrorDescriptionFromTokenEndpointResponseError.ts";
import { ValidateErrorFromTokenEndpointResponseError } from "../condition/client/ValidateErrorFromTokenEndpointResponseError.ts";
import { ValidateErrorUriFromTokenEndpointResponseError } from "../condition/client/ValidateErrorUriFromTokenEndpointResponseError.ts";
import { ValidateExpiresIn } from "../condition/client/ValidateExpiresIn.ts";
import { ValidateIdTokenFromTokenResponseEncryption } from "../condition/client/ValidateIdTokenFromTokenResponseEncryption.ts";
import { VerifyIdTokenSubConsistentHybridFlow } from "../condition/client/VerifyIdTokenSubConsistentHybridFlow.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ConditionResult, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// New test not present in python suite
export class OIDCCEnsureClientAssertionWithIssAudSucceeds extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-client-assertion-with-iss-aud-succeeds",
		displayName: "OIDCC: client_assertion with AS issuer ID succeeds at the token endpoint",
		summary:
			"This test passes a client assertion where 'aud' is the Authorization Server's Issuer ID instead of the token endpoint. Per RFC7523-3 and Connect Core 1.0 - 3, the AS must verify that it is the intended audience, but only recommended a value. The AS should accept the AS Issuer ID as valid, but as a recommended value, the AS may reject it with a valid error response and the test will end with a WARNING, which will not affect certification.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [
			{ parameter: ClientAuthType, values: ["client_secret_basic", "client_secret_post", "mtls", "none"] },
		],
	};

	protected override async performPostAuthorizationFlow(): Promise<void> {
		if (this.responseType.includesCode()) {
			// call the token endpoint and check response
			await this.createAuthorizationCodeRequest();
			await this.requestAuthorizationCode();
			// stop after checking token endpoint response
		}
		await this.onPostAuthorizationFlowComplete();
	}

	protected override async createAuthorizationCodeRequest(): Promise<void> {
		await this.callAndStopOnFailure(CreateTokenEndpointRequestForAuthorizationCodeGrant);
		if (this.addTokenEndpointClientAuthentication != null) {
			this.mapClientAuthKeys("token_endpoint_request_form_parameters", "token_endpoint_request_headers");
			await this.call(
				this.sequenceOf(this.sequence(this.addTokenEndpointClientAuthentication)).insertAfter(
					CreateClientAuthenticationAssertionClaims,
					this.condition(UpdateClientAuthenticationAssertionClaimsWithISSAud),
				),
			);
			this.unmapClientAuthKeys();
		}
	}

	protected override async requestAuthorizationCode(): Promise<void> {
		await this.callAndStopOnFailure(CallTokenEndpointAndReturnFullResponse);

		/* If we get an error back from the token endpoint server:
		 * - It must be a 'invalid_client' error
		 */
		if (this.env.getString("token_endpoint_response", "error")) {
			await this.callAndContinueOnFailure(CheckIfTokenEndpointResponseError, ConditionResult.WARNING);
			await this.callAndContinueOnFailure(
				CheckTokenEndpointReturnedJsonContentType,
				ConditionResult.FAILURE,
				"OIDCC-3.1.3.4",
			);
			await this.callAndContinueOnFailure(
				ValidateErrorFromTokenEndpointResponseError,
				ConditionResult.FAILURE,
				"RFC6749-5.2",
			);
			await this.callAndContinueOnFailure(
				CheckErrorDescriptionFromTokenEndpointResponseErrorContainsCRLFTAB,
				ConditionResult.WARNING,
				"RFC6749-5.2",
			);
			await this.callAndContinueOnFailure(
				ValidateErrorDescriptionFromTokenEndpointResponseError,
				ConditionResult.FAILURE,
				"RFC6749-5.2",
			);
			await this.callAndContinueOnFailure(
				ValidateErrorUriFromTokenEndpointResponseError,
				ConditionResult.FAILURE,
				"RFC6749-5.2",
			);
			await this.callAndContinueOnFailure(
				CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError,
				ConditionResult.FAILURE,
				"RFC6749-5.2",
			);
			await this.callAndContinueOnFailure(
				CheckErrorFromTokenEndpointResponseErrorInvalidClient,
				ConditionResult.FAILURE,
				"RFC6749-5.2",
			);
		} else {
			await this.callAndStopOnFailure(CheckIfTokenEndpointResponseError);
			await this.callAndStopOnFailure(CheckForAccessTokenValue);
			await this.callAndStopOnFailure(ExtractAccessTokenFromTokenResponse);

			await this.callAndContinueOnFailure(
				ExtractExpiresInFromTokenEndpointResponse,
				ConditionResult.INFO,
				"RFC6749-5.1",
			); // this is 'recommended' by the RFC, but we don't want to raise a warning on every test
			await this.skipIfMissing(
				["expires_in"],
				null,
				ConditionResult.INFO,
				ValidateExpiresIn,
				ConditionResult.FAILURE,
				"RFC6749-5.1",
			);

			await this.callAndContinueOnFailure(CheckForRefreshTokenValue, ConditionResult.INFO);

			await this.skipIfMissing(
				["client_jwks"],
				null,
				ConditionResult.INFO,
				ValidateIdTokenFromTokenResponseEncryption,
				ConditionResult.WARNING,
				"OIDCC-10.2",
			);
			await this.callAndStopOnFailure(ExtractIdTokenFromTokenResponse, "OIDCC-3.1.3.3", "OIDCC-3.3.3.3");

			// save the id_token returned from the token endpoint
			this.env.putObject("token_endpoint_id_token", this.env.getObject("id_token"));

			await this.additionalTokenEndpointResponseValidation();

			if (this.responseType.includesIdToken()) {
				await this.callAndContinueOnFailure(VerifyIdTokenSubConsistentHybridFlow, ConditionResult.FAILURE, "OIDCC-2");
			}
		}
	}
}
