import { CallUserInfoEndpoint } from "../condition/client/CallUserInfoEndpoint.ts";
import { EnsureContentTypeJson } from "../condition/client/EnsureContentTypeJson.ts";
import { EnsureHttpStatusCodeIs200 } from "../condition/client/EnsureHttpStatusCodeIs200.ts";
import { EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources } from "../condition/client/EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources.ts";
import { EnsureUserInfoContainsSub } from "../condition/client/EnsureUserInfoContainsSub.ts";
import { EnsureUserInfoUpdatedAtValid } from "../condition/client/EnsureUserInfoUpdatedAtValid.ts";
import { ExtractUserInfoFromUserInfoEndpointResponse } from "../condition/client/ExtractUserInfoFromUserInfoEndpointResponse.ts";
import { ValidateUserInfoStandardClaims } from "../condition/client/ValidateUserInfoStandardClaims.ts";
import { VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub } from "../condition/client/VerifyUserInfoAndIdTokenInAuthorizationEndpointSameSub.ts";
import { VerifyUserInfoAndIdTokenInTokenEndpointSameSub } from "../condition/client/VerifyUserInfoAndIdTokenInTokenEndpointSameSub.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import { ConditionResult, type ModuleVariantMetadata } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// can't call userinfo endpoint if there's no access token, so exclude response_type=id_token
export abstract class AbstractOIDCCUserInfoTest extends AbstractOIDCCServerTest {
	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token"] }],
	};

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		await this.callUserInfoEndpoint();
		await this.extractUserInfoResponse();
		await this.validateExtractedUserInfoResponse();
		await this.fireTestFinished();
	}

	protected async extractUserInfoResponse(): Promise<void> {
		await this.call(this.exec().mapKey("endpoint_response", "userinfo_endpoint_response_full"));
		await this.callAndContinueOnFailure(EnsureContentTypeJson, ConditionResult.FAILURE, "OIDCC-5.3.2");
		await this.call(this.exec().unmapKey("endpoint_response"));
		await this.callAndStopOnFailure(ExtractUserInfoFromUserInfoEndpointResponse);
	}

	protected async callUserInfoEndpoint(): Promise<void> {
		await this.callAndStopOnFailure(CallUserInfoEndpoint, "OIDCC-5.3.1");
		await this.call(this.exec().mapKey("endpoint_response", "userinfo_endpoint_response_full"));
		await this.callAndContinueOnFailure(EnsureHttpStatusCodeIs200, ConditionResult.FAILURE);
		await this.call(this.exec().unmapKey("endpoint_response"));
	}

	protected async validateExtractedUserInfoResponse(): Promise<void> {
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

			if (this.responseType.includesCode()) {
				await this.callAndContinueOnFailure(
					VerifyUserInfoAndIdTokenInTokenEndpointSameSub,
					ConditionResult.FAILURE,
					"OIDCC-5.3.2",
				);
			}
		}
	}
}
