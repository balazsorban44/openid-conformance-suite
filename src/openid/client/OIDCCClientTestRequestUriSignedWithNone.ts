import type { ModuleVariantMetadata, PublishTestModule } from "../../framework/index.ts";
import { EnsureRequestObjectWasSignedWithNone } from "../../condition/as/EnsureRequestObjectWasSignedWithNone.ts";
import { EnsureRequestObjectSigningAlgIsNoneInClientMetadata } from "../../condition/as/dynregistration/EnsureRequestObjectSigningAlgIsNoneInClientMetadata.ts";
import { ClientRequestType } from "../../variant/ClientRequestType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestRequestUriSignedWithNone extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-request-uri-signed-none",
		displayName: "OIDCC: Relying party test, request_uri support with 'none' signing algorithm",
		summary:
			"The client is expected to pass a request object by reference (and complete the entire flow), " +
			"using the request_uri parameter. The request object must be signed using 'none' algorithm." +
			" Corresponds to rp-request_uri-unsigned test in the old test suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRequestType, values: ["plain_http_request", "request_object"] }],
	};

	protected override getEffectiveClientRequestTypeVariant(): ClientRequestType {
		return ClientRequestType.REQUEST_URI;
	}

	protected override async validateClientMetadata(): Promise<void> {
		await super.validateClientMetadata();
		await this.callAndStopOnFailure(EnsureRequestObjectSigningAlgIsNoneInClientMetadata);
	}

	protected override async validateRequestObject(): Promise<void> {
		await super.validateRequestObject();
		await this.callAndStopOnFailure(EnsureRequestObjectWasSignedWithNone);
	}
}
