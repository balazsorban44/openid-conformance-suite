import { BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint } from "../condition/client/BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint.ts";
import { ConvertAuthorizationEndpointRequestToRequestObject } from "../condition/client/ConvertAuthorizationEndpointRequestToRequestObject.ts";
import { SerializeRequestObjectWithNullAlgorithm } from "../condition/client/SerializeRequestObjectWithNullAlgorithm.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import {
	AbstractConditionSequence,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCRequestUriServerTest } from "./AbstractOIDCCRequestUriServerTest.ts";

// https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_request_uri_Unsigned
export class OIDCCRequestUriUnsigned extends AbstractOIDCCRequestUriServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-request-uri-unsigned",
		displayName: "OIDCC: Unsigned request_uri",
		summary:
			"This test calls the authorization endpoint as normal, but passes a request_uri that points at an unsigned jwt. The authorization server must successfully complete the authorization, as request_uri is a mandatory to support feature for dynamic OPs as per OpenID Connect Core section 15.2. Support for unsigned jwts(alg=none) is not required if the server supports signed algorithms; this test will be skipped if none is not listed in the server's discovery endpoint request_object_signing_alg_values_supported.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		this.skipTestIfNoneUnsupported();
	}

	protected override async createAuthorizationRedirect(): Promise<void> {
		await this.call(new CreateAuthorizationRedirectSteps());
	}
}

// Java: nested public static class OIDCCRequestUriUnsigned.CreateAuthorizationRedirectSteps (declared after the
// module class so scripts/gen-registry.ts does not mistake it for the module)
export class CreateAuthorizationRedirectSteps extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(ConvertAuthorizationEndpointRequestToRequestObject);

		this.callAndStopOnFailure(SerializeRequestObjectWithNullAlgorithm);

		this.callAndStopOnFailure(BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint);
	}
}
