import { AddInvalidRedirectUriToAuthorizationRequest } from "../condition/client/AddInvalidRedirectUriToAuthorizationRequest.ts";
import { ConvertAuthorizationEndpointRequestToRequestObject } from "../condition/client/ConvertAuthorizationEndpointRequestToRequestObject.ts";
import { EnsureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri } from "../condition/client/EnsureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri.ts";
import { ExpectRedirectUriErrorPage } from "../condition/common/ExpectRedirectUriErrorPage.ts";
import { type PublishTestModule } from "../framework/index.ts";
import { CreateAuthorizationRedirectSteps } from "./AbstractOIDCCRequestObjectServerTest.ts";
import { AbstractOIDCCRequestObjectServerTestExpectingRedirectOrPlaceholder } from "./AbstractOIDCCRequestObjectServerTestExpectingRedirectOrPlaceholder.ts";

// This does not correspond to a particular OIDC python test
export class OIDCCEnsureRequestObjectWithRedirectUri extends AbstractOIDCCRequestObjectServerTestExpectingRedirectOrPlaceholder {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-request-object-with-redirect-uri",
		displayName: "OIDCC: ensure request object redirect_uri takes precedence",
		summary:
			"This test includes two redirect URIs, one in the request object (passed by value) " +
			"and one as a normal request parameter. The server must either use the redirect_uri in the request object " +
			"(as per OIDCC-6.1) and process the authentication correctly, " +
			"or show an invalid redirect_uri error - upload a screenshot of the error page. " +
			"This is an extra test that wasn't present in the python suite, and ensures implementations are " +
			"processing request objects correctly. The test will be skipped if the server discovery document indicates the server only supports signed request objects (i.e. the server does not support unsigned request objects, indicated by 'request_object_signing_alg_values_supported' not containing 'none').",
		profile: "OIDCC",
	};

	protected override async createAuthorizationRedirect(): Promise<void> {
		await this.call(
			new CreateAuthorizationRedirectSteps().insertAfter(
				ConvertAuthorizationEndpointRequestToRequestObject,
				this.condition(AddInvalidRedirectUriToAuthorizationRequest).requirement("OIDCC-6.1"),
			),
		);
	}

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectRedirectUriErrorPage, "RFC6749-3.1.2");

		this.env.putString("error_callback_placeholder", this.env.getString("redirect_uri_error"));
	}

	protected override async onAuthorizationCallbackResponse(): Promise<void> {
		const error = this.env.getString("authorization_endpoint_response", "error");
		if (error != null && error === "request_not_supported") {
			//this is unexpected as the redirect_uri outside the request object was invalid
			//but we received a redirect to the correct redirect_uri
			await this.callAndStopOnFailure(EnsureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri);
		}
		await super.onAuthorizationCallbackResponse();
	}
}
