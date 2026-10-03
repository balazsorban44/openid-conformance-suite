import {
	ProfileNames,
	SpecFamilyNames,
	TestPlan,
	type PublishTestPlan,
	type VariantSelection,
} from "../../framework/index.ts";
import { OIDCCClient3rdPartyInitiatedLoginTest } from "./OIDCCClient3rdPartyInitiatedLoginTest.ts";

export class OIDCCClient3rdPartyInitiatedLoginTestPlan extends TestPlan {
	static override readonly meta: PublishTestPlan = {
		testPlanName: "oidcc-client-test-3rd-party-init-login-test-plan",
		displayName: "OpenID Connect Core Client Login Tests: Relying party 3rd party initiated login tests",
		profile: ProfileNames.rptest,
		specFamily: SpecFamilyNames.oidcc,
		testModules: [OIDCCClient3rdPartyInitiatedLoginTest],
	};

	override certificationProfileName(_variant: VariantSelection): string[] {
		return ["3rd Party-Init RP"];
	}
}
