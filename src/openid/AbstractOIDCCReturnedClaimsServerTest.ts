import { CallUserInfoEndpoint } from "../condition/client/CallUserInfoEndpoint.ts";
import { EnsureHttpStatusCodeIs200 } from "../condition/client/EnsureHttpStatusCodeIs200.ts";
import { EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources } from "../condition/client/EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources.ts";
import { EnsureUserInfoContainsSub } from "../condition/client/EnsureUserInfoContainsSub.ts";
import { EnsureUserInfoUpdatedAtValid } from "../condition/client/EnsureUserInfoUpdatedAtValid.ts";
import { ExtractUserInfoFromUserInfoEndpointResponse } from "../condition/client/ExtractUserInfoFromUserInfoEndpointResponse.ts";
import { OIDCCCheckScopesSupportedContainScopeTest } from "../condition/client/OIDCCCheckScopesSupportedContainScopeTest.ts";
import { ValidateUserInfoStandardClaims } from "../condition/client/ValidateUserInfoStandardClaims.ts";
import { VerifyScopesReturnedInAuthorizationEndpointIdToken } from "../condition/client/VerifyScopesReturnedInAuthorizationEndpointIdToken.ts";
import { VerifyScopesReturnedInUserInfoClaims } from "../condition/client/VerifyScopesReturnedInUserInfoClaims.ts";
import { VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub } from "../condition/client/VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub.ts";
import { VerifyUserInfoAndIdTokenInTokenEndpointSameSub } from "../condition/client/VerifyUserInfoAndIdTokenInTokenEndpointSameSub.ts";
import { ConditionResult } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

/**
 * Base class for tests that request that the OP return particular claims
 */
export class AbstractOIDCCReturnedClaimsServerTest extends AbstractOIDCCServerTest {
	protected override async skipTestIfScopesNotSupported(): Promise<void> {
		if (this.serverSupportsDiscovery()) {
			await this.callAndContinueOnFailure(OIDCCCheckScopesSupportedContainScopeTest, ConditionResult.INFO);

			const scopesSupportedFlag = this.env.getBoolean("scopes_not_supported_flag");
			if (scopesSupportedFlag != null && scopesSupportedFlag) {
				this.fireTestSkipped(
					"scopes_supported from the discovery endpoint indicates the server doesn't support the scopes required for this test; so the test has been skipped",
				);
			}
		}
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		// Verify scopes returned in userinfo endpoint if we have access token
		// and otherwise in returned id_token from authorization endpoint
		if (this.responseType.includesCode() || this.responseType.includesToken()) {
			await this.callUserInfoEndpoint();
			await this.callAndStopOnFailure(ExtractUserInfoFromUserInfoEndpointResponse);
			await this.validateUserInfoResponse();
		} else {
			await this.validateIdTokenForResponseTypeIdToken();
		}

		await this.fireTestFinished();
	}

	protected async validateIdTokenForResponseTypeIdToken(): Promise<void> {
		await this.callAndContinueOnFailure(
			VerifyScopesReturnedInAuthorizationEndpointIdToken,
			ConditionResult.WARNING,
			"OIDCC-5.4",
		);
	}

	protected async callUserInfoEndpoint(): Promise<void> {
		await this.callAndStopOnFailure(CallUserInfoEndpoint, "OIDCC-5.3.1");
		await this.call(this.exec().mapKey("endpoint_response", "userinfo_endpoint_response_full"));
		await this.callAndContinueOnFailure(EnsureHttpStatusCodeIs200, ConditionResult.FAILURE);
		await this.call(this.exec().unmapKey("endpoint_response"));
	}

	protected async validateUserInfoResponse(): Promise<void> {
		await this.callAndContinueOnFailure(ValidateUserInfoStandardClaims, ConditionResult.FAILURE, "OIDCC-5.1");
		await this.callAndContinueOnFailure(EnsureUserInfoContainsSub, ConditionResult.FAILURE, "OIDCC-5.3.2");
		await this.callAndContinueOnFailure(EnsureUserInfoUpdatedAtValid, ConditionResult.FAILURE, "OIDCC-5.1");
		await this.callAndContinueOnFailure(
			EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources,
			ConditionResult.FAILURE,
			"OIDCC-5.6.2",
		);

		if (this.responseType.includesIdToken()) {
			await this.callAndContinueOnFailure(
				VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub,
				ConditionResult.FAILURE,
				"OIDCC-5.3.2",
			);
		}
		if (this.responseType.includesCode()) {
			await this.callAndContinueOnFailure(
				VerifyUserInfoAndIdTokenInTokenEndpointSameSub,
				ConditionResult.FAILURE,
				"OIDCC-5.3.2",
			);
		}
		await this.callAndContinueOnFailure(VerifyScopesReturnedInUserInfoClaims, ConditionResult.WARNING, "OIDCC-5.4");
	}
}
