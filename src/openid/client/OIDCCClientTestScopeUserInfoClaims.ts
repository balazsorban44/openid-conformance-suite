import type { PublishTestModule } from "../../framework/index.ts";
import { AddUserinfoClaimsToIdTokenClaims } from "../../condition/as/AddUserinfoClaimsToIdTokenClaims.ts";
import { EnsureScopeContainsAtLeastOneOfProfileEmailPhoneAddress } from "../../condition/as/EnsureScopeContainsAtLeastOneOfProfileEmailPhoneAddress.ts";
import { FilterUserInfoForScopes } from "../../condition/as/FilterUserInfoForScopes.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestScopeUserInfoClaims extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-scope-userinfo-claims",
		displayName: "OIDCC: Relying party test. Request claims using scope values.",
		summary:
			"The client is expected to request claims using one of more of the following scope values: " +
			"profile, email, phone, address." +
			" If no access token is issued (when using Implicit Flow with response_type='id_token') " +
			"the ID Token contains the requested claims." +
			" Corresponds to rp-scope-userinfo-claims in the old suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	protected override async validateAuthorizationEndpointRequestParameters(): Promise<void> {
		await super.validateAuthorizationEndpointRequestParameters();
		await this.callAndStopOnFailure(EnsureScopeContainsAtLeastOneOfProfileEmailPhoneAddress);
	}

	protected override async generateIdTokenClaims(): Promise<void> {
		await super.generateIdTokenClaims();
		//when no Access Token is issued (which is the case for the response_type value id_token),
		//the resulting Claims are returned in the ID Token.
		if (
			this.responseType.includesIdToken() &&
			!this.responseType.includesCode() &&
			!this.responseType.includesToken()
		) {
			await this.callAndStopOnFailure(FilterUserInfoForScopes, "OIDCC-5.4");
			await this.callAndStopOnFailure(AddUserinfoClaimsToIdTokenClaims, "OIDCC-5.4");
		}
	}
}
