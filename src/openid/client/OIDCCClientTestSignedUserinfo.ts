import type { ModuleVariantMetadata, PublishTestModule } from "../../framework/index.ts";
import { SetUserinfoSignedResponseAlgToRS256 } from "../../condition/as/SetUserinfoSignedResponseAlgToRS256.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestSignedUserinfo extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-userinfo-signed",
		displayName: "OIDCC: Relying party test, request and validate signed userinfo",
		summary:
			"The client is expected to make an authentication request " +
			"(also a token request where applicable) and a userinfo request " +
			"using the selected response_type and other configuration options and " +
			"userinfo_signed_response_alg RS256. ",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token"] }],
	};

	protected override async validateClientMetadata(): Promise<void> {
		await super.validateClientMetadata();
		await this.callAndStopOnFailure(SetUserinfoSignedResponseAlgToRS256);
	}
}
