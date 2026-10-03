import { AddAudToRequestObject } from "../condition/client/AddAudToRequestObject.ts";
import { AddIssToRequestObject } from "../condition/client/AddIssToRequestObject.ts";
import { AddRequestObjectSigningAlgRS256ToDynamicRegistrationRequest } from "../condition/client/AddRequestObjectSigningAlgRS256ToDynamicRegistrationRequest.ts";
import { BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint } from "../condition/client/BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint.ts";
import { CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256 } from "../condition/client/CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256.ts";
import { ConvertAuthorizationEndpointRequestToRequestObject } from "../condition/client/ConvertAuthorizationEndpointRequestToRequestObject.ts";
import { SetScopeInClientConfigurationToOpenId } from "../condition/client/SetScopeInClientConfigurationToOpenId.ts";
import { SignRequestObject } from "../condition/client/SignRequestObject.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import {
	AbstractConditionSequence,
	ConditionResult,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCRequestUriServerTest } from "./AbstractOIDCCRequestUriServerTest.ts";

// https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_request_uri_Sig
export class OIDCCRequestUriSignedRS256 extends AbstractOIDCCRequestUriServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-request-uri-signed-rs256",
		displayName: "OIDCC: RS256 signed request object passed by reference (request_uri)",
		summary:
			"This test calls the authorization endpoint as normal, but passes a request_uri that points at an RS256 signed JWS. The authorization server must successfully complete the authorization - whilst the OpenID Connect Core specification does not require support of RS256 signed request objects, the 'dynamic' certification profile does.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ClientRegistration, values: ["static_client"] }],
	};

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		await this.callAndContinueOnFailure(
			CheckDiscEndpointRequestObjectSigningAlgValuesSupportedContainsRS256,
			ConditionResult.FAILURE,
			"OIDCD-3",
		);
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();

		await this.callAndStopOnFailure(AddRequestObjectSigningAlgRS256ToDynamicRegistrationRequest);
	}

	protected override async createAuthorizationRedirect(): Promise<void> {
		let keysMapped = false;
		try {
			// The flow is slightly different when using client_secret_jwt client authentication.
			// It has to map 'client_jwks' to the saved 'rsa_client_jwks' so that the RSA keys can be
			// used to sign the request object
			const rsaClientJwks = this.env.getObject("rsa_client_jwks");
			if (this.getVariant(ClientAuthType) === ClientAuthType.CLIENT_SECRET_JWT && rsaClientJwks != null) {
				this.env.mapKey("client_jwks", "rsa_client_jwks");
				keysMapped = true;
			}
			await this.call(new CreateAuthorizationRedirectSteps());
		} finally {
			if (keysMapped) {
				this.env.unmapKey("client_jwks");
			}
		}
	}

	protected override async completeClientConfiguration(): Promise<void> {
		await this.callAndStopOnFailure(SetScopeInClientConfigurationToOpenId);

		if (this.profileCompleteClientConfiguration != null) {
			// When using client_secret_jwt client authentication, the client secret JWK
			// generated overwrites the RSA keys used for signing the Request object with
			// RS256 algorithm, so we need to save the RSA key first so we can use it later
			const clientJwk = this.env.getObject("client_jwks");
			if (this.getVariant(ClientAuthType) === ClientAuthType.CLIENT_SECRET_JWT && clientJwk != null) {
				this.env.putObject("rsa_client_jwks", clientJwk);
			}
			await this.call(this.sequence(this.profileCompleteClientConfiguration));
		}
	}
}

// Java: nested public static class OIDCCRequestUriSignedRS256.CreateAuthorizationRedirectSteps (declared after the
// module class so scripts/gen-registry.ts does not mistake it for the module)
export class CreateAuthorizationRedirectSteps extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(ConvertAuthorizationEndpointRequestToRequestObject);

		// aud/iss weren't sent in the python, but are recommended by the spec so we send them
		this.callAndStopOnFailure(AddAudToRequestObject, "OIDCC-6.1");
		this.callAndStopOnFailure(AddIssToRequestObject, "OIDCC-6.1");

		this.callAndStopOnFailure(SignRequestObject);

		this.callAndStopOnFailure(BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint);
	}
}
