import { AddMaxAge10000ToAuthorizationEndpointRequest } from "../condition/client/AddMaxAge10000ToAuthorizationEndpointRequest.ts";
import { AddMaxAge15000ToAuthorizationEndpointRequest } from "../condition/client/AddMaxAge15000ToAuthorizationEndpointRequest.ts";
import { CheckIdTokenAuthTimeClaimPresentDueToMaxAge } from "../condition/client/CheckIdTokenAuthTimeClaimPresentDueToMaxAge.ts";
import { ConditionResult, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCSameAuthTwiceServerTest } from "./AbstractOIDCCSameAuthTwiceServerTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Req_max_age=10000
export class OIDCCMaxAge10000 extends AbstractOIDCCSameAuthTwiceServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-max-age-10000",
		displayName: "OIDCC: Use max_age=10000 in authorization request when already logged in",
		summary:
			"This test calls the authorization endpoint test twice. The first time it includes max_age=15000 (so that the OP is required to return auth_time in the id_token). The second time it includes max_age=10000, and the authorization server must not request that the user logs in. The test verifies that auth_time and sub are consistent between the id_tokens from the first and second authorizations.",
		profile: "OIDCC",
	};

	protected override async createFirstAuthorizationRequest(): Promise<void> {
		// This differs from the python test, where max_age was not included and hence the test could not check that
		// auth_time was consistent as many OPs (correctly) won't return auth_time unless max_age or an essential
		// claim for auth_time is present - and claims are optional to implement, so max_age is the only choice to
		// force auth_time to be returned.
		// discussed on the certification email list 3rd March 2020
		await this.call(
			this.createAuthorizationRequestSequence().then(
				this.condition(AddMaxAge15000ToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1", "OIDCC-15.1"),
			),
		);
	}

	protected override async createSecondAuthorizationRequest(): Promise<void> {
		await this.call(
			this.createAuthorizationRequestSequence().then(
				this.condition(AddMaxAge10000ToAuthorizationEndpointRequest).requirements("OIDCC-3.1.2.1", "OIDCC-15.1"),
			),
		);
	}

	protected override async validateFirstIdToken(): Promise<void> {
		await this.callAndContinueOnFailure(
			CheckIdTokenAuthTimeClaimPresentDueToMaxAge,
			ConditionResult.FAILURE,
			"OIDCC-2",
			"OIDCC-3.1.2.1",
			"OIDCC-15.1",
		);
		await super.validateFirstIdToken();
	}

	protected override async validateFirstAndSecondIdTokens(): Promise<void> {
		// max_age is requested second time, so auth_time must be present
		await this.callAndContinueOnFailure(
			CheckIdTokenAuthTimeClaimPresentDueToMaxAge,
			ConditionResult.FAILURE,
			"OIDCC-2",
			"OIDCC-3.1.2.1",
			"OIDCC-15.1",
		);
		await super.validateFirstAndSecondIdTokens();
	}
}
