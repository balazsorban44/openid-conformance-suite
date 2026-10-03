import { AddQueryToRedirectUri } from "../condition/client/AddQueryToRedirectUri.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_redirect_uri_Query_OK
export class OIDCCRedirectUriQueryOK extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-redirect-uri-query-OK",
		displayName:
			"OIDCC: request with a redirect_uri with a query component when a redirect_uri with the same query component is registered",
		summary: "This test uses a redirect uri with a query component. Authorization should complete successfully.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async configureDynamicClient(): Promise<void> {
		await this.callAndStopOnFailure(AddQueryToRedirectUri);
		this.exposeEnvString("redirect_uri");
		await super.configureDynamicClient();
	}
}
