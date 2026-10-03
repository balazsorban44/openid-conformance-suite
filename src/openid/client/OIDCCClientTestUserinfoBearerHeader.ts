import type { ModuleVariantMetadata, PublishTestModule } from "../../framework/index.ts";
import { EnsureBearerAccessTokenNotInParams } from "../../condition/rs/EnsureBearerAccessTokenNotInParams.ts";
import { ExtractBearerAccessTokenFromHeader } from "../../condition/rs/ExtractBearerAccessTokenFromHeader.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestUserinfoBearerHeader extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-userinfo-bearer-header",
		displayName: "OIDCC: Relying party test, pass the access token using Bearer authentication scheme",
		summary:
			"The client is expected to Pass the access token using the 'Bearer' authentication scheme while doing the UserInfo Request." +
			" Corresponds to rp-userinfo-bearer-header test in the old suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token"] }],
	};

	protected override async extractBearerTokenFromUserinfoRequest(): Promise<void> {
		await this.callAndStopOnFailure(ExtractBearerAccessTokenFromHeader, "RFC6750-2");
		await this.callAndStopOnFailure(EnsureBearerAccessTokenNotInParams, "RFC6750-2");
	}
}
