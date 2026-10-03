import { AddIdTokenSigningAlgRS256ToDynamicRegistrationRequest } from "../condition/client/AddIdTokenSigningAlgRS256ToDynamicRegistrationRequest.ts";
import { CheckIdTokenSignatureAlgorithm } from "../condition/client/CheckIdTokenSignatureAlgorithm.ts";
import { EnsureIdTokenContainsKid } from "../condition/client/EnsureIdTokenContainsKid.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ConditionResult, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to OPIdToken-kid and OP-IDToken-RS256
export class OIDCCIdTokenRS256 extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-idtoken-rs256",
		displayName: "OIDCC: check ID token with RS256 signature",
		summary: "This test requests an ID token signed with RS256.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		await this.callAndStopOnFailure(AddIdTokenSigningAlgRS256ToDynamicRegistrationRequest);
	}

	protected override async performIdTokenValidation(): Promise<void> {
		// OP-IDToken-kid
		// OIDCC-10.1 seems to only require a KID if the server has multiple JWKs,
		// but we'll replicate the python test here and require it always.
		await this.callAndContinueOnFailure(EnsureIdTokenContainsKid, ConditionResult.FAILURE, "OIDCC-10.1");
		// OP-IDToken-RS256
		await this.callAndContinueOnFailure(CheckIdTokenSignatureAlgorithm, ConditionResult.FAILURE, "OIDCC-3.1.3.7");
		await super.performIdTokenValidation();
	}
}
