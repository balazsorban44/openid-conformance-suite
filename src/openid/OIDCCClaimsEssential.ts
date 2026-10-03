import { AddIdTokenEssentialNameClaimToAuthorizationEndpointRequest } from "../condition/client/AddIdTokenEssentialNameClaimToAuthorizationEndpointRequest.ts";
import { AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest } from "../condition/client/AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest.ts";
import { EnsureIdTokenContainsName } from "../condition/client/EnsureIdTokenContainsName.ts";
import { EnsureIdTokenDoesNotContainName } from "../condition/client/EnsureIdTokenDoesNotContainName.ts";
import { EnsureUserInfoContainsName } from "../condition/client/EnsureUserInfoContainsName.ts";
import {
	ConditionResult,
	type ConditionClass,
	type ConditionSequence,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCReturnedClaimsServerTest } from "./AbstractOIDCCReturnedClaimsServerTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_claims_essential
export class OIDCCClaimsEssential extends AbstractOIDCCReturnedClaimsServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-claims-essential",
		displayName: "OIDCC: claims essential",
		summary:
			"This test makes an authorization request requesting the 'name' claim as essential (in the userinfo, except for response_type=id_token where it is requested in the id_token), and the OP must return a successful result. A warning is raised if the OP fails to return a value for the name claim.",
		profile: "OIDCC",
	};

	protected override async skipTestIfScopesNotSupported(): Promise<void> {}

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		let addClaim: ConditionClass = AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest;
		if (this.responseType.isIdToken()) {
			addClaim = AddIdTokenEssentialNameClaimToAuthorizationEndpointRequest;
		}
		return super
			.createAuthorizationRequestSequence()
			.then(this.condition(addClaim).requirements("OIDCC-5.5", "OIDCC-5.5.1"));
	}

	protected override async validateUserInfoResponse(): Promise<void> {
		await super.validateUserInfoResponse();
		await this.callAndContinueOnFailure(
			EnsureUserInfoContainsName,
			ConditionResult.WARNING,
			"OIDCC-5.5",
			"OIDCC-5.5.1",
		);
		// the python test did not check this as far as I know
		await this.callAndContinueOnFailure(
			EnsureIdTokenDoesNotContainName,
			ConditionResult.WARNING,
			"OIDCC-5.5",
			"OIDCC-5.5.1",
		);
	}

	protected override async validateIdTokenForResponseTypeIdToken(): Promise<void> {
		await super.validateIdTokenForResponseTypeIdToken();
		await this.callAndContinueOnFailure(EnsureIdTokenContainsName, ConditionResult.WARNING, "OIDCC-5.5", "OIDCC-5.5.1");
	}
}
