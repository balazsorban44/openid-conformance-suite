import type { JsonObject, ModuleVariantMetadata, PublishTestModule } from "../../framework/index.ts";
import { ChangeSubInUserInfoResponseToBeInvalid } from "../../condition/as/ChangeSubInUserInfoResponseToBeInvalid.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestInvalidSubInUserinfoResponse extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-userinfo-invalid-sub",
		displayName: "OIDCC: Relying party test, sub in userinfo response does not match id_token",
		summary:
			"The client is expected to make a userinfo request " +
			" and verify the 'sub' value of the UserInfo Response by comparing it with the ID Token's 'sub' value." +
			" The client must identify the invalid 'sub' value and reject the UserInfo Response." +
			" Corresponds to rp-userinfo-bad-sub-claim test in the old suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token"] }],
	};

	protected override async prepareUserinfoResponse(): Promise<JsonObject | null> {
		await super.prepareUserinfoResponse();
		await this.callAndStopOnFailure(ChangeSubInUserInfoResponseToBeInvalid, "OIDCC-5.3.2");
		const user = this.env.getObject("user_info_endpoint_response");
		return user;
	}
}
