import { BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint } from "../condition/client/BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint.ts";
import { CheckDiscEndpointRequestUriParameterSupported } from "../condition/client/CheckDiscEndpointRequestUriParameterSupported.ts";
import { ConvertAuthorizationEndpointRequestToRequestObject } from "../condition/client/ConvertAuthorizationEndpointRequestToRequestObject.ts";
import { SerializeRequestObjectWithNullAlgorithm } from "../condition/client/SerializeRequestObjectWithNullAlgorithm.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import {
	AbstractConditionSequence,
	ConditionResult,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCRequestUriServerTest } from "./AbstractOIDCCRequestUriServerTest.ts";

// https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_request_uri_Unsigned
export class OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported extends AbstractOIDCCRequestUriServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
		displayName: "OIDCC: Unsigned request_uri",
		summary:
			"This test calls the authorization endpoint as normal, but passes a request_uri that points at an unsigned jwt. The authorization server must successfully complete the authorization, or return a request_uri_not_supported error. This test will be skipped if none is not listed in the server's discovery endpoint request_object_signing_alg_values_supported.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		this.skipTestIfNoneUnsupported();
	}

	protected override async checkDiscEndpointRequestUriParameterSupported(): Promise<void> {
		// We deliberately skip the hard check for the request_uri_parameter_supported here, as we check for a request_uri_not_supported error later.
		// super.checkDiscEndpointRequestUriParameterSupported();
	}

	protected override async createAuthorizationRedirect(): Promise<void> {
		await this.call(new CreateAuthorizationRedirectSteps());
	}

	protected override async onAuthorizationCallbackResponse(): Promise<void> {
		const error = this.env.getString("authorization_endpoint_response", "error");
		if (error != null && error === "request_uri_not_supported") {
			// we don't check if state is correct here, as state was only passed inside the request object and hence
			// we can't expect the OP to return it
			this.fireTestSkipped(
				"The 'request_uri_not_supported' error from the authorization endpoint indicates that it does not support request_uri (which is permitted behaviour), so request_uri cannot be tested.",
			);
		}

		if (this.serverSupportsDiscovery()) {
			await this.callAndContinueOnFailure(CheckDiscEndpointRequestUriParameterSupported, ConditionResult.WARNING);
		}

		await super.onAuthorizationCallbackResponse();
	}
}

// Java: nested public static class (declared after the module class so scripts/gen-registry.ts does not mistake it
// for the module)
export class CreateAuthorizationRedirectSteps extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(ConvertAuthorizationEndpointRequestToRequestObject);

		this.callAndStopOnFailure(SerializeRequestObjectWithNullAlgorithm);

		this.callAndStopOnFailure(BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint);
	}
}
