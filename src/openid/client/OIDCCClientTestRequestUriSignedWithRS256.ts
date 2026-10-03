import type { ModuleVariantMetadata, PublishTestModule } from "../../framework/index.ts";
import { EnsureRequestObjectWasSignedWithRS256 } from "../../condition/as/EnsureRequestObjectWasSignedWithRS256.ts";
import { EnsureRequestObjectSigningAlgIsRS256InClientMetadata } from "../../condition/as/dynregistration/EnsureRequestObjectSigningAlgIsRS256InClientMetadata.ts";
import { ClientRequestType } from "../../variant/ClientRequestType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

export class OIDCCClientTestRequestUriSignedWithRS256 extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-request-uri-signed-rs256",
		displayName: "OIDCC: Relying party test, request_uri support with RS256 signing algorithm",
		summary:
			"The client is expected to pass a request object by reference (and complete the entire flow), " +
			"using the request_uri parameter. The request object must be signed using 'RS256' algorithm." +
			" Corresponds to rp-request_uri-sig test in the old test suite.",
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
		await this.callAndStopOnFailure(EnsureRequestObjectSigningAlgIsRS256InClientMetadata);
	}

	protected override async validateRequestObject(): Promise<void> {
		await super.validateRequestObject();
		await this.callAndStopOnFailure(EnsureRequestObjectWasSignedWithRS256);
	}
}
