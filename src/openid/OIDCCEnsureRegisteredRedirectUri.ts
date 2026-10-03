import { CreateBadRedirectUriByAppending } from "../condition/client/CreateBadRedirectUriByAppending.ts";
import { ExpectRedirectUriErrorPage } from "../condition/common/ExpectRedirectUriErrorPage.ts";
import {
	TestFailureException,
	type HttpSession,
	type IncomingHttpRequest,
	type JsonObject,
	type PublishTestModule,
} from "../framework/index.ts";
import { AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback } from "./AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback.ts";

// Corresponds to OP-redirect_uri-NotReg
export class OIDCCEnsureRegisteredRedirectUri extends AbstractOIDCCServerTestExpectingAuthorizationEndpointPlaceholderOrCallback {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-registered-redirect-uri",
		displayName: "OIDCC: ensure registered redirect URI",
		summary:
			"This test uses an unregistered redirect uri. The authorization server should display an error saying the redirect uri is invalid, a screenshot of which should be uploaded.",
		profile: "OIDCC",
	};

	protected override async onConfigure(_config: JsonObject, _baseUrl: string): Promise<void> {
		// create a random redirect URI
		await this.callAndStopOnFailure(CreateBadRedirectUriByAppending);

		// this is inserted by the create call above, expose it to the test environment for publication
		this.exposeEnvString("redirect_uri");
	}

	protected override async createPlaceholder(): Promise<void> {
		await this.callAndStopOnFailure(ExpectRedirectUriErrorPage, "OIDCC-3.1.2.1");

		this.env.putString("error_callback_placeholder", this.env.getString("redirect_uri_error"));
	}

	protected override async processCallback(): Promise<void> {
		throw new TestFailureException(
			this.getId(),
			"The authorization server called the registered redirect uri. This should not have happened as the client provided a bad redirect_uri in the request.",
		);
	}

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === this.env.getString("bad_redirect_path")) {
			throw new TestFailureException(
				this.getId(),
				"The authorization server redirected the user to the requested but randomised/unregistered redirect uri. This must not happen as the provided redirect uri could not have been registered.",
			);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}
}
