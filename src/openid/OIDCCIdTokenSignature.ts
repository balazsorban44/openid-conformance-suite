import { EnsureIdTokenContainsKid } from "../condition/client/EnsureIdTokenContainsKid.ts";
import { EnsureIdTokenSignatureIsRS256 } from "../condition/client/EnsureIdTokenSignatureIsRS256.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ConditionResult, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to OPIdToken-kid and OP-IDToken-ignature
export class OIDCCIdTokenSignature extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-idtoken-signature",
		displayName: "OIDCC: check ID token with default signature",
		summary: "This test requests an ID token without specifying an algorithm (which should default to RS256).",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();
		// Don't specify an ID token signing algorithm
	}

	protected override async performIdTokenValidation(): Promise<void> {
		// OP-IDToken-kid
		// OIDCC-10.1 seems to only require a KID if the server has multiple JWKs,
		// but we'll replicate the python test here and require it always.
		await this.callAndContinueOnFailure(EnsureIdTokenContainsKid, ConditionResult.FAILURE, "OIDCC-10.1");
		await this.callAndContinueOnFailure(EnsureIdTokenSignatureIsRS256, ConditionResult.FAILURE, "OIDCC-3.1.3.7");
		await super.performIdTokenValidation();
	}
}
