import { BuildRequestObjectByValueRedirectToAuthorizationEndpoint } from "../condition/client/BuildRequestObjectByValueRedirectToAuthorizationEndpoint.ts";
import { CheckDiscEndpointRequestParameterSupported } from "../condition/client/CheckDiscEndpointRequestParameterSupported.ts";
import { ConvertAuthorizationEndpointRequestToRequestObject } from "../condition/client/ConvertAuthorizationEndpointRequestToRequestObject.ts";
import { SerializeRequestObjectWithNullAlgorithm } from "../condition/client/SerializeRequestObjectWithNullAlgorithm.ts";
import { AbstractConditionSequence, ConditionResult, type JsonObject } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export class CreateAuthorizationRedirectSteps extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(ConvertAuthorizationEndpointRequestToRequestObject);

		this.callAndStopOnFailure(SerializeRequestObjectWithNullAlgorithm);

		this.callAndStopOnFailure(BuildRequestObjectByValueRedirectToAuthorizationEndpoint);
	}
}

export class AbstractOIDCCRequestObjectServerTest extends AbstractOIDCCServerTest {
	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		this.skipTestIfNoneUnsupported();
	}

	protected override async createAuthorizationRedirect(): Promise<void> {
		await this.call(new CreateAuthorizationRedirectSteps());
	}

	protected override async onAuthorizationCallbackResponse(): Promise<void> {
		const error = this.env.getString("authorization_endpoint_response", "error");
		if (error != null && error === "request_not_supported") {
			// we don't check if state is correct here, as state was only passed inside the request object and hence
			// we can't expect the OP to return it
			this.fireTestSkipped(
				"The 'request_not_supported' error from the authorization endpoint indicates that it does not support request objects (which is permitted behaviour), so request objects cannot be tested.",
			);
		}

		if (this.serverSupportsDiscovery()) {
			await this.callAndContinueOnFailure(CheckDiscEndpointRequestParameterSupported, ConditionResult.WARNING);
		}

		await super.onAuthorizationCallbackResponse();
	}
}
