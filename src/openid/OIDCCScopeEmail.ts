import { EnsureIdTokenDoesNotContainEmailForScopeEmail } from "../condition/client/EnsureIdTokenDoesNotContainEmailForScopeEmail.ts";
import { EnsureIdTokenDoesNotContainName } from "../condition/client/EnsureIdTokenDoesNotContainName.ts";
import { EnsureUserInfoDoesNotContainName } from "../condition/client/EnsureUserInfoDoesNotContainName.ts";
import { SetScopeInClientConfigurationToOpenIdEmail } from "../condition/client/SetScopeInClientConfigurationToOpenIdEmail.ts";
import { ConditionResult, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCReturnedClaimsServerTest } from "./AbstractOIDCCReturnedClaimsServerTest.ts";

// Corresponds to OP-scope-email
export class OIDCCScopeEmail extends AbstractOIDCCReturnedClaimsServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-scope-email",
		displayName: "OIDCC: check email scope",
		summary:
			"This test requests authorization with email scope and issues a warning if an email address isn't returned in the expected place. As per OpenID Connect Core section 5.4, 'The Claims requested by the profile, email, address, and phone scope values are returned from the UserInfo Endpoint', except for response_type=id_token, where they are returned in the id_token (as there is no access token issued that could be used to access the userinfo endpoint).",
		profile: "OIDCC",
	};

	protected override async skipTestIfScopesNotSupported(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenIdEmail);
		await super.skipTestIfScopesNotSupported();
	}

	protected override async performIdTokenValidation(): Promise<void> {
		await super.performIdTokenValidation();

		// the python test did not check this as far as I know
		await this.callAndContinueOnFailure(
			EnsureIdTokenDoesNotContainName,
			ConditionResult.WARNING,
			"OIDCC-5.5",
			"OIDCC-5.5.1",
		);

		if (this.responseType.includesCode() || this.responseType.includesToken()) {
			// we have an access token so response should not be in id_token
			await this.callAndContinueOnFailure(
				EnsureIdTokenDoesNotContainEmailForScopeEmail,
				ConditionResult.WARNING,
				"OIDCC-5.4",
			);
		}
	}

	protected override async validateUserInfoResponse(): Promise<void> {
		await super.validateUserInfoResponse();

		await this.callAndContinueOnFailure(
			EnsureUserInfoDoesNotContainName,
			ConditionResult.WARNING,
			"OIDCC-5.5",
			"OIDCC-5.5.1",
		);
	}
}
