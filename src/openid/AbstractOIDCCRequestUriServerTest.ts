import { AddRequestUriToDynamicRegistrationRequest } from "../condition/client/AddRequestUriToDynamicRegistrationRequest.ts";
import { CheckDiscEndpointRequestUriParameterSupported } from "../condition/client/CheckDiscEndpointRequestUriParameterSupported.ts";
import { CreateRandomRequestUriWithFragment } from "../condition/common/CreateRandomRequestUriWithFragment.ts";
import {
	ConditionResult,
	DATAUTILS_MEDIATYPE_APPLICATION_JWT,
	responseEntity,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
} from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

/**
 * Generic behaviour required when testing request_uri behaviours
 */
export abstract class AbstractOIDCCRequestUriServerTest extends AbstractOIDCCServerTest {
	protected override async createDynamicClientRegistrationRequest(): Promise<void> {
		await super.createDynamicClientRegistrationRequest();

		await this.callAndStopOnFailure(CreateRandomRequestUriWithFragment, "OIDCC-6.2");
		await this.callAndStopOnFailure(AddRequestUriToDynamicRegistrationRequest);
	}

	protected override async onConfigure(config: JsonObject, baseUrl: string): Promise<void> {
		await super.onConfigure(config, baseUrl);
		await this.checkDiscEndpointRequestUriParameterSupported();
	}

	/**
	 * Allow derived tests to decide how to check for request_uri parameter support.
	 */
	protected async checkDiscEndpointRequestUriParameterSupported(): Promise<void> {
		await this.callAndContinueOnFailure(
			CheckDiscEndpointRequestUriParameterSupported,
			ConditionResult.FAILURE,
			"OIDCD-3",
		);
	}

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === this.env.getString("request_uri", "path")) {
			return this.handleRequestUriRequest();
		}
		return super.handleHttp(path, req, res, session, requestParts);
	}

	private handleRequestUriRequest(): Response {
		const requestObject = this.env.getString("request_object");

		return responseEntity(requestObject, 200, { "content-type": DATAUTILS_MEDIATYPE_APPLICATION_JWT });
	}

	protected abstract override createAuthorizationRedirect(): Promise<void>;
}
