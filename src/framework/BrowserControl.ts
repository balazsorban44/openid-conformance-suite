import type { BrowserContext, Locator, Page } from "@playwright/test";
import { ConditionResult } from "./Condition.ts";
import { args, ex } from "./DataUtils.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import type { TestExecutionManager } from "./execution.ts";
import { sleep } from "./execution.ts";
import { TestFailureException } from "./exceptions.ts";
import type { ImageService } from "./ImageService.ts";
import { isJsonArray, isJsonObject, OIDFJSON, type JsonArray, type JsonObject, type JsonValue } from "./json.ts";

/**
 * A user-supplied Playwright hook, the alternative to the JSON `browser` automation. Receives the page the suite
 * opened at `url` and drives the OP's login/consent screens until the redirect back to the suite completes.
 */
export type BrowserHook = (ctx: {
	page: Page;
	url: string;
	method: string;
	placeholder: string | null;
	log: (msg: string, extra?: Record<string, unknown>) => void;
}) => Promise<void>;

/**
 * Port of frontchannel/BrowserControl.java, driving a Playwright BrowserContext instead of HtmlUnit.
 *
 * The configuration format is unchanged from upstream:
 *
 *   "browser": [
 *     {
 *       "match": "https://op.example.com/authorize*",
 *       "tasks": [
 *         {
 *           "task": "Login",
 *           "match": "https://op.example.com/login*",
 *           "optional": true,
 *           "commands": [
 *             ["text", "id", "username", "user"],
 *             ["text", "id", "password", "password", "optional"],
 *             ["click", "name", "submit"],
 *             ["wait", "contains", "callback", 10]
 *           ]
 *         },
 *         { "task": "Verify Complete", "match": "*callback*" }
 *       ]
 *     }
 *   ]
 *
 * Commands: click, text, wait, wait-element-visible, wait-element-invisible. Selectors: id, name, xpath, css, class.
 * Alternatively a TypeScript config can supply a BrowserHook function as `browser`.
 */
export class BrowserControl {
	private readonly testId: string;
	private readonly executionManager: TestExecutionManager;
	private browserCommands: JsonArray = [];
	private hook: BrowserHook | null = null;
	private verboseLogging = false;
	private showQrCodes = false;

	private urls: string[] = [];
	private urlsWithMethod: { url: string; method: string }[] = [];
	private visited: string[] = [];
	private visitedUrlsWithMethod: { url: string; method: string }[] = [];
	private browserApiRequests: { request: JsonObject; submitUrl: string }[] = [];
	private uriInputRequests: { submitUrl: string; description: string }[] = [];
	private runners = new Set<WebRunner>();

	private readonly imageService: ImageService;
	private readonly eventLog: TestInstanceEventLog;
	private readonly context: () => Promise<BrowserContext>;
	/** Screenshots taken on failures / placeholders, for the report */
	readonly screenshots: { name: string; png: Buffer }[] = [];

	constructor(
		config: JsonObject | (JsonObject & { browser?: BrowserHook }),
		testId: string,
		eventLog: TestInstanceEventLog,
		executionManager: TestExecutionManager,
		imageService: ImageService,
		context: () => Promise<BrowserContext>,
	) {
		this.testId = testId;
		this.eventLog = eventLog;
		this.executionManager = executionManager;
		this.imageService = imageService;
		this.context = context;

		const browser = (config as Record<string, unknown>)["browser"];
		if (typeof browser === "function") {
			this.hook = browser as BrowserHook;
		} else if (isJsonArray(browser)) {
			this.browserCommands = browser;
		}
		const browserVerbose = config["browser_verbose"];
		if (browserVerbose != null) {
			this.verboseLogging = OIDFJSON.getBoolean(browserVerbose);
		}
	}

	/**
	 * Returns true if the test configuration contains a 'browser' automation entry matching the given url.
	 */
	urlMatchesBrowserAutomation(url: string): boolean {
		if (this.hook) {
			return true;
		}
		for (const commandsEl of this.browserCommands) {
			const commands = commandsEl as JsonObject;
			const urlMatcher = OIDFJSON.getString(commands["match"]);
			if (simpleMatch(urlMatcher, url)) {
				if ("match-limit" in commands && OIDFJSON.getInt(commands["match-limit"]) <= 0) {
					continue;
				}
				return true;
			}
		}
		return false;
	}

	/**
	 * Tell the front-end control that a url needs to be visited. If there is a matching browser configuration
	 * element, this will execute automatically. If there is no matching element, the url is made available for
	 * user interaction.
	 */
	goToUrl(url: string, placeholder: string | null = null, method = "GET", delaySeconds = 0): void {
		if (this.hook) {
			const wr = new WebRunner(this, url, null, placeholder, method, delaySeconds, this.hook);
			this.runners.add(wr);
			this.executionManager.runInBackground(() => wr.run(), "browser");
			return;
		}
		for (const commandsEl of this.browserCommands) {
			const commands = commandsEl as JsonObject;
			const urlMatcher = OIDFJSON.getString(commands["match"]);
			if (simpleMatch(urlMatcher, url)) {
				if ("match-limit" in commands) {
					let limit = OIDFJSON.getInt(commands["match-limit"]);
					if (limit <= 0) {
						continue;
					}
					limit--;
					commands["match-limit"] = limit;
				}
				const wr = new WebRunner(
					this,
					url,
					(commands["tasks"] as JsonArray) ?? [],
					placeholder,
					method,
					delaySeconds,
					null,
				);
				this.runners.add(wr);
				this.executionManager.runInBackground(() => wr.run(), "browser");
				return;
			}
		}
		if (this.verboseLogging) {
			this.eventLog.log("BROWSER", "asking user to visit url, no automation for found: " + url);
		}
		// if we couldn't find a command for this URL, leave it up to the user to do something with it
		this.urls.push(url);
		this.urlsWithMethod.push({ url, method });
	}

	requestCredential(request: JsonObject, submitUrl: string): void {
		this.browserApiRequests.push({ request, submitUrl });
	}

	requestUriInput(submitUrl: string, description: string): void {
		if (this.uriInputRequests.some((r) => r.submitUrl === submitUrl)) {
			return;
		}
		this.uriInputRequests.push({ submitUrl, description });
	}

	/** Tell the front end control that a url has been visited by the user externally. */
	urlVisited(url: string): void {
		this.urls = this.urls.filter((u) => u !== url);
		this.visited.push(url);
		const idx = this.urlsWithMethod.findIndex((u) => u.url === url);
		if (idx >= 0) {
			const [u] = this.urlsWithMethod.splice(idx, 1);
			this.visitedUrlsWithMethod.push(u);
		}
	}

	getUrls(): string[] {
		return this.urls;
	}

	getUrlsWithMethod(): { url: string; method: string }[] {
		return this.urlsWithMethod;
	}

	getBrowserApiRequests(): { request: JsonObject; submitUrl: string }[] {
		return this.browserApiRequests;
	}

	getUriInputRequests(): { submitUrl: string; description: string }[] {
		return this.uriInputRequests;
	}

	getVisitedUrlsWithMethod(): { url: string; method: string }[] {
		return this.visitedUrlsWithMethod;
	}

	getVisited(): string[] {
		return this.visited;
	}

	showQrCodes_(): boolean {
		return this.showQrCodes;
	}

	setShowQrCodes(showQrCodes: boolean): void {
		this.showQrCodes = showQrCodes;
	}

	getWebRunners(): JsonObject[] {
		return [...this.runners].map((wr) => wr.describe());
	}

	runnersActive(): boolean {
		return this.runners.size > 0;
	}

	// --- internals used by WebRunner ---

	/** @internal */
	_log(source: string, map: Record<string, unknown> | string): void {
		this.eventLog.log(source, map);
	}

	/** @internal */
	_verbose(): boolean {
		return this.verboseLogging;
	}

	/** @internal */
	_testId(): string {
		return this.testId;
	}

	/** @internal */
	async _newPage(): Promise<Page> {
		const ctx = await this.context();
		return ctx.newPage();
	}

	/** @internal */
	_runnerDone(wr: WebRunner): void {
		this.runners.delete(wr);
	}

	/** @internal */
	_addScreenshot(name: string, png: Buffer): void {
		this.screenshots.push({ name, png });
	}

	/**
	 * Publish the given page content to fulfill the placeholder.
	 * @internal
	 */
	_updatePlaceholder(
		placeholder: string | null,
		pageSource: string,
		responseContentType: string | null,
		regexp: string | null,
		optional: boolean,
		screenshot?: Buffer,
	): void {
		const update: Record<string, unknown> = {
			page_source: pageSource,
			content_type: responseContentType,
			matched_regexp: regexp,
		};
		if (screenshot) {
			update["img"] = "data:image/png;base64," + screenshot.toString("base64");
		}
		const document =
			placeholder == null ? null : this.imageService.fillPlaceholder(this.testId, placeholder, update, true);
		if (document == null) {
			if (optional) {
				this.eventLog.log(
					"BROWSER",
					args("msg", "Skipping optional placeholder update as placeholder not found.", "placeholder", placeholder),
				);
				return;
			}
			throw new TestFailureException(this.testId, "Couldn't find matched placeholder for uploading error screenshot.");
		}
		this.eventLog.log("BROWSER", args("msg", "Updated placeholder from scripted browser", "placeholder", placeholder));
		if (this.imageService.getRemainingPlaceholders(this.testId, true).length === 0) {
			this.eventLog.log("BROWSER", args("msg", "All placeholders filled by scripted browser"));
		}
	}
}

/**
 * Port of Spring's PatternMatchUtils.simpleMatch: "xxx*", "*xxx", "*xxx*" and "xxx*yyy" matches (with an
 * arbitrary number of pattern parts), as well as direct equality.
 */
export function simpleMatch(pattern: string | null, str: string | null): boolean {
	if (pattern == null || str == null) {
		return false;
	}
	const parts = pattern.split("*");
	if (parts.length === 1) {
		return pattern === str;
	}
	const re = new RegExp("^" + parts.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$", "s");
	return re.test(str);
}

/**
 * Port of BrowserControl.WebRunner: acts as the browser and allows goToUrl to return before the page gets hit.
 */
class WebRunner {
	private readonly control: BrowserControl;
	private readonly url: string;
	private readonly tasks: JsonArray | null;
	private readonly placeholder: string | null;
	private readonly method: string;
	private readonly delaySeconds: number;
	private readonly hook: BrowserHook | null;
	private page: Page | null = null;
	private currentTask: string | null = null;
	private currentCommand: string | null = null;
	private lastException: string | null = null;
	private lastResponseCode: number | null = null;
	private lastResponseContentType: string | null = null;
	private lastResponseContent: string | null = null;

	constructor(
		control: BrowserControl,
		url: string,
		tasks: JsonArray | null,
		placeholder: string | null,
		method: string,
		delaySeconds: number,
		hook: BrowserHook | null,
	) {
		this.control = control;
		this.url = url;
		this.tasks = tasks;
		this.placeholder = placeholder;
		this.method = method;
		this.delaySeconds = delaySeconds;
		this.hook = hook;
	}

	describe(): JsonObject {
		return {
			url: this.url,
			currentUrl: this.page?.url() ?? null,
			currentTask: this.currentTask,
			currentCommand: this.currentCommand,
			lastResponseCode: this.lastResponseCode,
			lastResponseContentType: this.lastResponseContentType,
			lastResponseContent: this.lastResponseContent,
			lastException: this.lastException,
		};
	}

	private testId(): string {
		return this.control._testId();
	}

	private currentUrl(): string {
		return this.page?.url() ?? "";
	}

	async run(): Promise<string> {
		const testId = this.testId();
		try {
			if (this.delaySeconds > 0) {
				await sleep(this.delaySeconds * 1000);
			}
			this.page = await this.control._newPage();
			const page = this.page;

			if (this.control._verbose()) {
				page.on("request", (req) => {
					this.control._log(
						"WebRunner",
						args(
							"msg",
							"Request " + req.method() + " " + req.url(),
							"headers",
							req.headers(),
							"body",
							req.postData(),
							"result",
							ConditionResult.INFO,
						),
					);
				});
				page.on("response", (res) => {
					const status = res.status();
					const msg =
						status === 302
							? `Redirect ${status} ${res.statusText()} to ${res.headers()["location"]} from ${res.request().method()} ${res.url()}`
							: `Response ${status} ${res.statusText()} ${res.request().method()} ${res.url()}`;
					this.control._log("WebRunner", args("msg", msg, "headers", res.headers(), "result", ConditionResult.INFO));
				});
				page.on("console", (m) => this.control._log("BROWSER", String(m.text())));
				page.on("pageerror", (e) =>
					this.control._log("BROWSER", args("msg", "Error during JavaScript execution", "detail", String(e))),
				);
			}

			// Consider this URL visited. Java records the visit after driver.get() returns; a user-driven browser
			// (urlVisited() from the UI) records it before the implementation under test redirects anywhere, which is what
			// e.g. oidcc-client-test-3rd-party-init-login checks for when the authorization request arrives, so the visit
			// is recorded when the navigation starts.
			this.control.urlVisited(this.url);

			let response;
			if (this.method === "POST") {
				const u = new URL(this.url);
				const params = u.search.startsWith("?") ? u.search.substring(1) : u.search;
				u.search = "";
				const urlWithoutQuery = u.toString();
				this.control._log(
					"WebRunner",
					args(
						"msg",
						"Scripted browser HTTP request",
						"http",
						"request",
						"request_uri",
						urlWithoutQuery,
						"parameters",
						params,
						"request_method",
						this.method,
						"browser",
						"goToUrl",
					),
				);
				// do the actual HTTP POST via an auto-submitting form, so the browser performs a real navigation
				const inputs = [...new URLSearchParams(params).entries()]
					.map(([k, v]) => `<input type="hidden" name="${escapeAttr(k)}" value="${escapeAttr(v)}">`)
					.join("");
				await page.setContent(
					`<html><body><form id="f" method="post" action="${escapeAttr(urlWithoutQuery)}">${inputs}</form></body></html>`,
				);
				// register the listeners before submitting so the (possibly immediate) response is not missed
				const responsePromise = page
					.waitForResponse((r) => r.request().isNavigationRequest() && r.url().startsWith(urlWithoutQuery), {
						timeout: 60_000,
					})
					.catch(() => null);
				const navigated = page.waitForURL((u) => u.protocol !== "about:", { timeout: 60_000, waitUntil: "load" });
				await page.evaluate('document.getElementById("f").submit()');
				await navigated;
				response = await responsePromise;
			} else {
				this.control._log(
					"WebRunner",
					args(
						"msg",
						"Scripted browser HTTP request",
						"http",
						"request",
						"request_uri",
						this.url,
						"request_method",
						this.method,
						"browser",
						"goToUrl",
					),
				);
				// do the actual HTTP GET
				response = await page.goto(this.url, { waitUntil: "load", timeout: 60_000 });
			}
			await this.recordResponse(response);

			this.control._log(
				"WebRunner",
				args(
					"msg",
					"Scripted browser HTTP response",
					"http",
					"response",
					"response_status_code",
					this.lastResponseCode,
					"response_status_text",
					this.status(),
					"response_content_type",
					this.lastResponseContentType,
					"response_content",
					this.lastResponseContent,
				),
			);

			if (this.hook) {
				await this.hook({
					page,
					url: this.url,
					method: this.method,
					placeholder: this.placeholder,
					log: (msg, extra) =>
						this.control._log("WebRunner", args("msg", msg, "browser", "hook", ...Object.entries(extra ?? {}).flat())),
				});
				if (this.placeholder) {
					await this.fillPlaceholder(null, true);
				}
				return "web runner exited";
			}

			for (const taskEl of this.tasks ?? []) {
				let skip = false;
				const currentTask = taskEl as JsonObject;
				if (currentTask["task"] == null) {
					throw new TestFailureException(testId, "Invalid Task Definition: no 'task' property");
				}
				const taskName = OIDFJSON.getString(currentTask["task"]);
				this.currentTask = taskName;

				let expectedUrlMatcher = "*"; // default to matching any URL
				if ("match" in currentTask) {
					expectedUrlMatcher = OIDFJSON.getString(currentTask["match"]);
				}

				if (expectedUrlMatcher) {
					if (!simpleMatch(expectedUrlMatcher, this.currentUrl())) {
						if ("optional" in currentTask && OIDFJSON.getBoolean(currentTask["optional"])) {
							this.control._log(
								"WebRunner",
								args(
									"msg",
									"Skipping optional task due to URL mismatch",
									"match",
									expectedUrlMatcher,
									"url",
									this.currentUrl(),
									"browser",
									"skip",
									"task",
									taskName,
									"commands",
									currentTask["commands"],
								),
							);
							skip = true;
						} else {
							this.control._log(
								"WebRunner",
								args(
									"msg",
									"Unexpected URL for non-optional task",
									"match",
									expectedUrlMatcher,
									"url",
									this.currentUrl(),
									"result",
									ConditionResult.FAILURE,
									"task",
									taskName,
									"commands",
									currentTask["commands"],
								),
							);
							throw new TestFailureException(testId, "WebRunner unexpected url for task: " + taskName);
						}
					}
				}

				if (!skip) {
					const commands = currentTask["commands"];
					if (commands != null && isJsonArray(commands)) {
						// wait for webpage to finish loading
						try {
							await page.waitForLoadState("load", { timeout: 10_000 });
						} catch (e) {
							this.control._log("BROWSER", ex(e, { msg: "Timeout waiting for page to load" }));
						}
						for (const command of commands) {
							await this.doCommand(command as JsonArray, taskName);
							this.currentCommand = null;
						}
					}

					await this.recordResponse(null);
					this.control._log(
						"WebRunner",
						args(
							"msg",
							"Completed processing of webpage",
							"match",
							expectedUrlMatcher,
							"url",
							this.currentUrl(),
							"browser",
							"complete",
							"task",
							taskName,
							"result",
							ConditionResult.INFO,
							"response_status_code",
							this.lastResponseCode,
							"response_status_text",
							this.status(),
						),
					);
				}
			}
			return "web runner exited";
		} catch (e) {
			const err = e as Error;
			let pageSource: string | null = null;
			let currentUrl: string | null = null;
			let screenshot: Buffer | undefined;
			try {
				if (this.page && !this.page.isClosed()) {
					currentUrl = this.page.url();
					pageSource = await this.page.content();
					screenshot = await this.page.screenshot({ fullPage: true });
					this.control._addScreenshot("webrunner-failure", screenshot);
				}
			} catch {
				// ignore
			}
			this.control._log(
				"WebRunner",
				ex(e, {
					msg: err.message,
					page_source: pageSource,
					url: currentUrl,
					content_type: this.lastResponseContentType,
					result: ConditionResult.FAILURE,
					img: screenshot ? "data:image/png;base64," + screenshot.toString("base64") : undefined,
				}),
			);
			this.lastException = err.message;
			if (e instanceof TestFailureException) {
				throw new TestFailureException(testId, "Web Runner Exception: " + err.message, e.cause);
			}
			throw new TestFailureException(testId, "Web Runner Exception: " + err.message, e);
		} finally {
			this.control._runnerDone(this);
			try {
				await this.page?.close();
			} catch {
				// ignore
			}
		}
	}

	private async recordResponse(
		response: { status(): number; statusText(): string; headers(): Record<string, string> } | null,
	): Promise<void> {
		if (response) {
			this.lastResponseCode = response.status();
			this.lastResponseContentType = response.headers()["content-type"] ?? null;
		}
		try {
			this.lastResponseContent = this.page && !this.page.isClosed() ? await this.page.content() : null;
		} catch {
			this.lastResponseContent = null;
		}
	}

	private status(): string {
		return this.lastResponseCode == null ? "" : `${this.lastResponseCode}-`;
	}

	private async fillPlaceholder(regexp: string | null, optional: boolean): Promise<void> {
		const page = this.page as Page;
		const screenshot = await page.screenshot({ fullPage: true }).catch(() => undefined);
		if (screenshot) {
			this.control._addScreenshot("placeholder-" + (this.placeholder ?? "none"), screenshot);
		}
		this.control._updatePlaceholder(
			this.placeholder,
			await page.content(),
			this.lastResponseContentType,
			regexp,
			optional,
			screenshot,
		);
	}

	/**
	 * Given a command like ["click","id","btnId"], perform the Playwright calls to execute it.
	 */
	private async doCommand(command: JsonArray, taskName: string): Promise<void> {
		const testId = this.testId();
		const page = this.page as Page;
		const commandString = OIDFJSON.getString(command[0]);
		if (!commandString) {
			this.lastException = "Invalid Command " + commandString;
			throw new TestFailureException(testId, "Invalid Command: " + commandString);
		}
		this.currentCommand = commandString;
		const elementType = OIDFJSON.getString(command[1]);
		const target = OIDFJSON.getString(command[2]);
		const cmd = commandString.toLowerCase();

		if (cmd === "click") {
			// ["click", "id" or "name", "id_or_name", "optional"]
			this.control._log(
				"WebRunner",
				args(
					"msg",
					"Clicking an element",
					"url",
					this.currentUrl(),
					"browser",
					commandString,
					"task",
					taskName,
					"element_type",
					elementType,
					"target",
					target,
					"result",
					ConditionResult.INFO,
				),
			);
			const locator = this.getSelector(elementType, target).first();
			const optional = command.length >= 4 ? OIDFJSON.getString(command[3]) : null;
			if ((await locator.count()) === 0) {
				if (optional === "optional") {
					this.control._log(
						"WebRunner",
						args(
							"msg",
							"Element not found, skipping as 'click' command is marked 'optional'",
							"url",
							this.currentUrl(),
							"browser",
							commandString,
							"task",
							taskName,
							"element_type",
							elementType,
							"target",
							target,
							"result",
							ConditionResult.INFO,
						),
					);
					return;
				}
				throw new TestFailureException(testId, `Unable to locate element: ${elementType} '${target}'`);
			}
			const navigation = page.waitForNavigation({ timeout: 10_000 }).catch(() => null);
			await locator.click({ timeout: 10_000 });
			await navigation;
			await page.waitForLoadState("load", { timeout: 10_000 }).catch(() => {});
		} else if (cmd === "text") {
			// ["text", "id" or "name", "id_or_name", "text_to_enter", "optional"]
			const value = OIDFJSON.getString(command[3]);
			this.control._log(
				"WebRunner",
				args(
					"msg",
					"Entering text",
					"url",
					this.currentUrl(),
					"browser",
					commandString,
					"task",
					taskName,
					"element_type",
					elementType,
					"target",
					target,
					"value",
					value,
					"result",
					ConditionResult.INFO,
				),
			);
			const locator = this.getSelector(elementType, target).first();
			const optional = command.length >= 5 ? OIDFJSON.getString(command[4]) : null;
			if ((await locator.count()) === 0) {
				if (optional === "optional") {
					this.control._log(
						"WebRunner",
						args(
							"msg",
							"Element not found, skipping as 'text' command is marked 'optional'",
							"url",
							this.currentUrl(),
							"browser",
							commandString,
							"task",
							taskName,
							"element_type",
							elementType,
							"target",
							target,
							"value",
							value,
							"result",
							ConditionResult.INFO,
						),
					);
					return;
				}
				throw new TestFailureException(testId, `Unable to locate element: ${elementType} '${target}'`);
			}
			await locator.fill(value, { timeout: 10_000 });
		} else if (cmd === "wait") {
			// ["wait","match" or "contains", "urlmatch_or_contains_string", timeout_in_seconds, regexp?, action?]
			const timeoutSeconds = OIDFJSON.getInt(command[3]);
			const regexp = command.length >= 5 ? OIDFJSON.getString(command[4]) : null;
			const action = command.length >= 6 ? OIDFJSON.getString(command[5]) : null;
			let updateImagePlaceHolder = false;
			let updateImagePlaceHolderOptional = false;
			if (action) {
				if (action === "update-image-placeholder-optional") {
					updateImagePlaceHolderOptional = true;
				} else if (action === "update-image-placeholder") {
					updateImagePlaceHolder = true;
				} else {
					this.lastException = "Invalid action: " + action;
					throw new TestFailureException(testId, "Invalid action: " + action);
				}
			}
			this.control._log(
				"WebRunner",
				args(
					"msg",
					"Waiting",
					"url",
					this.currentUrl(),
					"browser",
					commandString,
					"task",
					taskName,
					"element_type",
					elementType,
					"target",
					target,
					"seconds",
					timeoutSeconds,
					"result",
					ConditionResult.INFO,
					"regexp",
					regexp,
					"action",
					action,
				),
			);
			const timeout = timeoutSeconds * 1000;
			try {
				if (elementType.toLowerCase() === "contains") {
					await page.waitForURL((u) => u.toString().includes(target), { timeout, waitUntil: "commit" });
				} else if (elementType.toLowerCase() === "match") {
					const re = new RegExp(target);
					await page.waitForURL((u) => re.test(u.toString()), { timeout, waitUntil: "commit" });
				} else if (regexp) {
					const re = new RegExp(regexp);
					const locator = this.getSelector(elementType, target).first();
					const deadline = Date.now() + timeout;
					let matched = false;
					while (Date.now() < deadline) {
						const text = (await locator.textContent({ timeout: 500 }).catch(() => null)) ?? "";
						if (re.test(text)) {
							matched = true;
							break;
						}
						await sleep(100);
					}
					if (!matched) {
						throw new Error("timeout");
					}
					if (updateImagePlaceHolder || updateImagePlaceHolderOptional) {
						await this.fillPlaceholder(regexp, updateImagePlaceHolderOptional);
					}
				} else {
					await this.getSelector(elementType, target).first().waitFor({ state: "attached", timeout });
				}
			} catch (e) {
				this.lastException = (e as Error).message;
				throw new TestFailureException(testId, "Timed out waiting: " + JSON.stringify(command));
			}
		} else if (cmd === "wait-element-invisible") {
			const timeoutSeconds = OIDFJSON.getInt(command[3]);
			try {
				await this.getSelector(elementType, target)
					.first()
					.waitFor({ state: "hidden", timeout: timeoutSeconds * 1000 });
			} catch (e) {
				this.lastException = (e as Error).message;
				throw new TestFailureException(
					testId,
					"Timed out waiting for element to become invisible: " + JSON.stringify(command),
				);
			}
		} else if (cmd === "wait-element-visible") {
			const timeoutSeconds = OIDFJSON.getInt(command[3]);
			try {
				await this.getSelector(elementType, target)
					.first()
					.waitFor({ state: "visible", timeout: timeoutSeconds * 1000 });
			} catch (e) {
				this.lastException = (e as Error).message;
				throw new TestFailureException(testId, "Timed out waiting for element visibility: " + JSON.stringify(command));
			}
		} else {
			this.lastException = "Invalid Command " + commandString;
			throw new TestFailureException(testId, "Invalid Command: " + commandString);
		}
	}

	/**
	 * Returns the appropriate Playwright locator based on type and value.
	 * Currently supports id, name, xpath, css (css selector), and class (html class)
	 */
	private getSelector(type: string, value: string): Locator {
		const page = this.page as Page;
		switch (type.toLowerCase()) {
			case "id":
				return page.locator(`[id=${JSON.stringify(value)}]`);
			case "name":
				return page.locator(`[name=${JSON.stringify(value)}]`);
			case "xpath":
				return page.locator(`xpath=${value}`);
			case "css":
				return page.locator(value);
			case "class":
				return page.locator(`.${value.split(/\s+/).join(".")}`);
			default:
				this.lastException = "Invalid Command Selector: Type: " + type + " Value: " + value;
				throw new TestFailureException(this.testId(), "Invalid Command Selector: Type: " + type + " Value: " + value);
		}
	}
}

function escapeAttr(s: string): string {
	return s.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;");
}

export function isBrowserConfig(v: JsonValue | undefined): v is JsonArray {
	return isJsonArray(v) && v.every((x) => isJsonObject(x));
}
