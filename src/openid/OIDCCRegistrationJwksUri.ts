import { AddJwksUriToDynamicRegistrationRequest } from "../condition/client/AddJwksUriToDynamicRegistrationRequest.ts";
import { AddPublicJwksToDynamicRegistrationRequest } from "../condition/client/AddPublicJwksToDynamicRegistrationRequest.ts";
import { CreateJwksUri } from "../condition/client/CreateJwksUri.ts";
import { GenerateRS256ClientJWKs } from "../condition/client/GenerateRS256ClientJWKs.ts";
import { GenerateRS256ClientJWKsWithKeyID } from "../condition/client/GenerateRS256ClientJWKsWithKeyID.ts";
import { OIDCCCreateDynamicClientRegistrationRequest } from "../sequence/client/OIDCCCreateDynamicClientRegistrationRequest.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import {
	jsonResponse,
	TestFailureException,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Corresponds to https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_Registration_jwks_uri
export class OIDCCRegistrationJwksUri extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-registration-jwks-uri",
		displayName: "OIDCC: dynamic registration with JWKS URI",
		summary:
			"This test calls the dynamic registration endpoint with a jwks URI, and continues with authorization. This should result in a successful registration and authorization.",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [
			{
				parameter: ClientAuthType,
				values: ["none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "mtls"],
			},
			{ parameter: ResponseType, values: ["id_token", "id_token token"] },
			{ parameter: ClientRegistration, values: ["static_client"] },
		],
	};

	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await this.callAndStopOnFailure(CreateJwksUri);
		await this.call(
			new OIDCCCreateDynamicClientRegistrationRequest(this.responseType)
				.replace(GenerateRS256ClientJWKs, this.condition(GenerateRS256ClientJWKsWithKeyID))
				.replace(AddPublicJwksToDynamicRegistrationRequest, this.condition(AddJwksUriToDynamicRegistrationRequest)),
		);
		this.expose("client_name", this.env.getString("dynamic_registration_request", "client_name"));
	}

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === "client1_jwks") {
			return this.handleJwksRequest();
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	private handleJwksRequest(): Response {
		const clientPublicJwks = this.env.getObject("client_public_jwks");
		if (clientPublicJwks == null) {
			throw new TestFailureException(
				this.getId(),
				"jwks endpoint called before key exists - please wait for test to initialise before calling client jwks endpoint",
			);
		}
		return jsonResponse(clientPublicJwks, 200);
	}
}
