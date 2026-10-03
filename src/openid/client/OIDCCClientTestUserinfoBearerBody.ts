import type { ModuleVariantMetadata, PublishTestModule } from "../../framework/index.ts";
import { OIDCCExtractBearerAccessTokenFromBodyParams } from "../../condition/rs/OIDCCExtractBearerAccessTokenFromBodyParams.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestUserinfoBearerBody extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-userinfo-bearer-body",
		displayName: "OIDCC: Relying party test, pass the access token as form-encoded body parameter",
		summary:
			"The client is expected to pass the access token " +
			"as form-encoded body parameter while doing the UserInfo Request." +
			" Corresponds to rp-userinfo-bearer-body test in the old suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token"] }],
	};

	protected override async extractBearerTokenFromUserinfoRequest(): Promise<void> {
		await this.callAndStopOnFailure(OIDCCExtractBearerAccessTokenFromBodyParams, "RFC6750-2");
	}
}
