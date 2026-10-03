import { AddSectorIdentifierUriToDynamicRegistrationRequest } from "../condition/client/AddSectorIdentifierUriToDynamicRegistrationRequest.ts";
import { AddSubjectTypePairwiseToDynamicRegistrationRequest } from "../condition/client/AddSubjectTypePairwiseToDynamicRegistrationRequest.ts";
import { CallDynamicRegistrationEndpoint } from "../condition/client/CallDynamicRegistrationEndpoint.ts";
import { CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata } from "../condition/client/CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata.ts";
import { CreateInvalidSectorRedirectUris } from "../condition/client/CreateInvalidSectorRedirectUris.ts";
import { EnsureContentTypeJson } from "../condition/client/EnsureContentTypeJson.ts";
import { EnsureHttpStatusCodeIs400 } from "../condition/client/EnsureHttpStatusCodeIs400.ts";
import {
	ConditionResult,
	isJsonArray,
	jsonArrayContains,
	jsonResponse,
	OIDFJSON,
	Status,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonArray,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCDynamicRegistrationTest } from "./AbstractOIDCCDynamicRegistrationTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Registration_Sector_Bad
export class OIDCCRegistrationSectorBad extends AbstractOIDCCDynamicRegistrationTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-registration-sector-bad",
		displayName: "OIDCC: dynamic registration with bad sector redirect URIs",
		summary:
			"This test calls the dynamic registration endpoint with a sector_identifier_uri pointing to a document not containing the test's redirect URI. This should result in an error from the dynamic registration endpoint.",
		profile: "OIDCC",
	};

	protected override async onConfigure(_config: JsonObject, _baseUrl: string): Promise<void> {
		const server = this.env.getObject("server") as JsonObject;
		const subjectTypesSupported = server["subject_types_supported"];
		if (
			subjectTypesSupported == null ||
			!isJsonArray(subjectTypesSupported) ||
			!jsonArrayContains(subjectTypesSupported, "pairwise")
		) {
			this.fireTestSkipped("Server configuration does not explicitly support pairwise subject type");
		}
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.configureDynamicClient();
		// No authorization flow in this test
		await this.fireTestFinished();
	}

	protected override async configureDynamicClient(): Promise<void> {
		await this.callAndStopOnFailure(CreateInvalidSectorRedirectUris);

		await this.createDynamicClientRegistrationRequest();

		this.expose("client_name", this.env.getString("dynamic_registration_request", "client_name"));

		await this.callAndStopOnFailure(CallDynamicRegistrationEndpoint, "OIDCR-5");

		this.env.mapKey("endpoint_response", "dynamic_registration_endpoint_response");
		await this.callAndContinueOnFailure(EnsureContentTypeJson, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(EnsureHttpStatusCodeIs400, ConditionResult.FAILURE);
		await this.callAndContinueOnFailure(
			CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata,
			ConditionResult.WARNING,
			"OIDCR-3.3",
		);
	}

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();

		await this.callAndStopOnFailure(AddSubjectTypePairwiseToDynamicRegistrationRequest);
		await this.callAndStopOnFailure(AddSectorIdentifierUriToDynamicRegistrationRequest);
	}

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === "redirect_uris.json") {
			return this.handleRedirectUrisRequest();
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected override async performAuthorizationFlow(): Promise<void> {
		// Not used in this test
	}

	private handleRedirectUrisRequest(): Response {
		const value = (this.env.getObject("sector_redirect_uris") as JsonObject)["value"] as JsonArray;
		return jsonResponse(
			value.map((v) => OIDFJSON.getString(v)),
			200,
		);
	}
}
