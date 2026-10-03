import { AddSectorIdentifierUriToDynamicRegistrationRequest } from "../condition/client/AddSectorIdentifierUriToDynamicRegistrationRequest.ts";
import { AddSubjectTypePairwiseToDynamicRegistrationRequest } from "../condition/client/AddSubjectTypePairwiseToDynamicRegistrationRequest.ts";
import { CreateSectorRedirectUris } from "../condition/client/CreateSectorRedirectUris.ts";
import {
	isJsonArray,
	jsonArrayContains,
	jsonResponse,
	OIDFJSON,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonArray,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCDynamicRegistrationTest } from "./AbstractOIDCCDynamicRegistrationTest.ts";

export class OIDCCRegistrationSectorUri extends AbstractOIDCCDynamicRegistrationTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-registration-sector-uri",
		displayName: "OIDCC: dynamic registration",
		summary:
			"This test calls the dynamic registration endpoint with a sector_identifier_uri pointing to a document containing the test's redirect URI. This should result in a successful registration.",
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
		await this.callAndStopOnFailure(CreateSectorRedirectUris);
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
		// Don't need to test authorization here.
		await this.fireTestFinished();
	}

	private handleRedirectUrisRequest(): Response {
		const value = (this.env.getObject("sector_redirect_uris") as JsonObject)["value"] as JsonArray;
		return jsonResponse(
			value.map((v) => OIDFJSON.getString(v)),
			200,
		);
	}
}
