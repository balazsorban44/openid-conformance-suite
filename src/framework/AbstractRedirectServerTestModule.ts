import { AbstractTestModule } from "./AbstractTestModule.ts";
import { args } from "./DataUtils.ts";
import { sleep } from "./execution.ts";
import { TestFailureException } from "./exceptions.ts";
import { isJsonObject, OIDFJSON, type JsonObject } from "./json.ts";
import { Status, type HttpSession, type IncomingHttpRequest } from "./TestModule.ts";
import { modelAndView, noContent } from "./views.ts";

/**
 * Port of testmodule/AbstractRedirectServerTestModule.java
 *
 * The module is a general purpose module for collecting the result from the authorization endpoint.
 * TestModules using this class will receive the full result of the redirect in processCallback().
 */
export abstract class AbstractRedirectServerTestModule extends AbstractTestModule {
	// This isn't enabled by default as it would tie up a lot of threads in the CI
	protected abortIfRedirectFragmentNotReceived = false;

	// Incremented each time we successfully receive the full result for a redirect
	private currentRedirect = 0;

	protected callbackEndpoint = "callback";

	override async handleHttp(
		path: string,
		req: IncomingHttpRequest,
		res: unknown,
		session: HttpSession,
		requestParts: JsonObject,
	): Promise<Response> {
		if (path === this.callbackEndpoint) {
			return this.handleCallback(requestParts);
		} else if (path === this.env.getString("implicit_submit", "path")) {
			return this.handleImplicitSubmission(requestParts);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}

	protected redirect(redirectTo: string, method = "GET"): void {
		this.browser.goToUrl(redirectTo, null, method);
	}

	protected async performRedirect(method = "GET"): Promise<void> {
		const redirectTo = this.env.getString("redirect_to_authorization_endpoint") as string;

		this.eventLog.log(
			this.getName(),
			args(
				"msg",
				"Redirecting to authorization endpoint",
				"redirect_to",
				redirectTo,
				"method",
				method,
				"http",
				"redirect",
			),
		);

		await this.setStatus(Status.WAITING);

		this.redirect(redirectTo, method);
	}

	protected async performRedirectAndWaitForPlaceholdersOrCallback(
		placeholderKey = "error_callback_placeholder",
		method = "GET",
	): Promise<void> {
		const redirectTo = this.env.getString("redirect_to_authorization_endpoint") as string;

		this.eventLog.log(
			this.getName(),
			args("msg", "Redirecting to authorization endpoint", "redirect_to", redirectTo, "http", "redirect"),
		);

		await this.createPlaceholder();

		await this.setStatus(Status.WAITING);

		this.waitForPlaceholders();

		this.browser.goToUrl(redirectTo, this.env.getString(placeholderKey), method);
	}

	// performs the redirect with a placeholder to fill in, but does NOT start 'waitForPlaceholders()' so
	// this is used when the test will continue running after the redirect
	protected async performRedirectWithPlaceholder(method = "GET"): Promise<void> {
		const redirectTo = this.env.getString("redirect_to_authorization_endpoint") as string;

		this.eventLog.log(
			this.getName(),
			args("msg", "Redirecting to authorization endpoint", "redirect_to", redirectTo, "http", "redirect"),
		);

		await this.createPlaceholder();

		await this.setStatus(Status.WAITING);

		this.browser.goToUrl(redirectTo, this.env.getString("error_callback_placeholder"), method);
	}

	protected async createPlaceholder(): Promise<void> {
		// Use for create new placeholder in subclass
		throw new TestFailureException(this.getId(), "Placeholder must be created for test " + this.getName());
	}

	private async handleCallback(requestParts: JsonObject): Promise<Response> {
		await this.setStatus(Status.RUNNING);

		const bodyFormParams = requestParts["body_form_params"];
		if (bodyFormParams != null && isJsonObject(bodyFormParams)) {
			this.env.putObject("callback_body_form_params", bodyFormParams);
		}
		this.env.putObject("callback_query_params", requestParts["query_string_params"] as JsonObject);
		this.env.putObject("callback_headers", requestParts["headers"] as JsonObject);
		this.env.putString("callback_http_method", OIDFJSON.getString(requestParts["method"]));

		const { CreateRandomImplicitSubmitUrl } = await import("../condition/common/CreateRandomImplicitSubmitUrl.ts");
		await this.callAndStopOnFailure(CreateRandomImplicitSubmitUrl);

		await this.setStatus(Status.WAITING);

		if (this.abortIfRedirectFragmentNotReceived) {
			const waitTimeoutSeconds = 20;
			const thisRedirect = this.currentRedirect;
			this.getTestExecutionManager().runInBackground(async () => {
				await sleep(waitTimeoutSeconds * 1000, this.getTestExecutionManager().signal);
				if (this.getStatus() === Status.WAITING) {
					await this.setStatus(Status.RUNNING);
					if (this.currentRedirect === thisRedirect) {
						throw new TestFailureException(
							this.getId(),
							"The fragment has not been submitted by the user's browser. The URL may not have been opened in a web browser, or the JavaScript has not run for some other reason.",
						);
					}
				}
				return "done";
			});
		}

		return modelAndView("implicitCallback", {
			implicitSubmitUrl: this.env.getString("implicit_submit", "fullUrl"),
			returnUrl: "/log-detail.html?log=" + this.getId(),
		});
	}

	/**
	 * Called after the redirect response has been fully received. These will be available in the environment:
	 *
	 * 'callback_params': fragment passed to redirect uri
	 * 'callback_query_params': url query passed to redirect uri
	 * 'callback_http_method': http method used at redirect uri (usually GET or POST)
	 * 'callback_body_form_params': any form encoded body passed to redirect uri
	 */
	protected abstract processCallback(): Promise<void>;

	private async handleImplicitSubmission(requestParts: JsonObject): Promise<Response> {
		this.getTestExecutionManager().runInBackground(async () => {
			// process the callback
			await this.setStatus(Status.RUNNING);
			this.currentRedirect++;

			const body = requestParts["body"];
			if (body != null) {
				this.env.putString("implicit_hash", OIDFJSON.getString(body));
			} else {
				this.env.putString("implicit_hash", ""); // Clear any old value
			}

			const { ExtractImplicitHashToCallbackResponse } =
				await import("../condition/client/ExtractImplicitHashToCallbackResponse.ts");
			await this.callAndStopOnFailure(ExtractImplicitHashToCallbackResponse);

			this.eventLog.log(
				this.getName(),
				args(
					"msg",
					"Authorization endpoint response captured",
					"http",
					"redirect-in",
					"http_method",
					this.env.getString("callback_http_method"),
					"url_query",
					this.env.getObject("callback_query_params"),
					"url_fragment",
					this.env.getObject("callback_params"),
					"headers",
					this.env.getObject("callback_headers"),
					"post_body",
					this.env.getObject("callback_body_form_params"),
				),
			);

			await this.processCallback();

			return "done";
		}, "implicit submission");

		return noContent();
	}
}
