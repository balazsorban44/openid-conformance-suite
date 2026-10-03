import { AddUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest } from "../condition/client/AddUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest.ts";
import { CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256 } from "../condition/client/CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256.ts";
import { EnsureContentTypeApplicationJwt } from "../condition/client/EnsureContentTypeApplicationJwt.ts";
import { EnsureUserInfoDoesNotContainNonce } from "../condition/client/EnsureUserInfoDoesNotContainNonce.ts";
import { ExtractSignedUserInfoFromUserInfoEndpointResponse } from "../condition/client/ExtractSignedUserInfoFromUserInfoEndpointResponse.ts";
import { ValidateSignedUserInfoResponseStandardJWTClaims } from "../condition/client/ValidateSignedUserInfoResponseStandardJWTClaims.ts";
import { ValidateUserInfoResponseSignature } from "../condition/client/ValidateUserInfoResponseSignature.ts";
import { ValidateUserInfoSigningAlgIsRS256 } from "../condition/client/ValidateUserInfoSigningAlgIsRS256.ts";
import { OIDCCCreateDynamicClientRegistrationRequest } from "../sequence/client/OIDCCCreateDynamicClientRegistrationRequest.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import {
	ConditionResult,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCUserInfoTest } from "./AbstractOIDCCUserInfoTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_UserInfo_RS256
export class OIDCCUserInfoRS256 extends AbstractOIDCCUserInfoTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-userinfo-rs256",
		displayName: "OIDCC: Userinfo RS256 ",
		summary:
			"This test register a client with userinfo_signed_response_alg=RS256 and validates the signed response from the userinfo endpoint",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		await this.callAndContinueOnFailure(
			CheckDiscEndpointUserinfoSigningAlgValuesSupportedContainsRS256,
			ConditionResult.FAILURE,
			"OIDCD-3",
		);
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await this.call(
			new OIDCCCreateDynamicClientRegistrationRequest(this.responseType).then(
				this.condition(AddUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest).requirement("OIDCR-2"),
			),
		);

		this.expose("client_name", this.env.getString("dynamic_registration_request", "client_name"));
	}

	protected override async extractUserInfoResponse(): Promise<void> {
		await this.call(this.exec().mapKey("endpoint_response", "userinfo_endpoint_response_full"));
		await this.callAndContinueOnFailure(EnsureContentTypeApplicationJwt, ConditionResult.FAILURE, "OIDCC-5.3.2");
		await this.call(this.exec().unmapKey("endpoint_response"));

		await this.callAndContinueOnFailure(ValidateUserInfoResponseSignature, ConditionResult.FAILURE, "OIDCC-5.3.2");
		// should probably also use AbstractVerifyJwsSignatureUsingKid at some point

		await this.callAndStopOnFailure(ExtractSignedUserInfoFromUserInfoEndpointResponse);

		await this.callAndContinueOnFailure(ValidateUserInfoSigningAlgIsRS256, ConditionResult.FAILURE);

		// This is just a warning since https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse is fairly
		// lax on what is required
		await this.callAndContinueOnFailure(
			ValidateSignedUserInfoResponseStandardJWTClaims,
			ConditionResult.WARNING,
			"OIDCC-5.3.2",
		);

		// This is not a 'must not' in the spec, but equally including nonce here is almost certainly a mistake by the
		// implementor there is nothing in the spec that suggests including nonce
		await this.callAndContinueOnFailure(
			EnsureUserInfoDoesNotContainNonce,
			ConditionResult.FAILURE,
			"OIDCC-5.3.2",
			"OIDCC-5.1",
		);
	}
}
