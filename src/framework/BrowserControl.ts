import type { BrowserContext, Locator, Page, Response as PageResponse } from "@playwright/test";
import { ConditionResult } from "./Condition.ts";
import { ex, type LogArgs } from "./DataUtils.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import type { TestExecutionManager } from "./execution.ts";
import { sleep } from "./execution.ts";
import { TestFailureException } from "./exceptions.ts";
import type { ImageService } from "./ImageService.ts";
import { isJsonArray, OIDFJSON, type JsonArray, type JsonObject, type JsonValue } from "./json.ts";

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

/** What a WebRunner uses of its BrowserControl */
interface RunnerContext {
	readonly testId: string;
	readonly verbose: boolean;
	log(source: string, map: LogArgs | string): void;
	newPage(): Promise<Page>;
	urlVisited(url: string): void;
	addScreenshot(name: string, png: Buffer): void;
	updatePlaceholder(
		placeholder: string | null,
		pageSource: string,
		responseContentType: string | null,
		regexp: string | null,
		optional: boolean,
		screenshot?: Buffer,
	): void;
	runnerDone(runner: WebRunner): void;
}

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

	private visited: string[] = [];
	private runners = new Set<WebRunner>();

	private readonly imageService: ImageService;
	private readonly eventLog: TestInstanceEventLog;
	private readonly runnerContext: RunnerContext;
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

		this.runnerContext = {
			testId,
			verbose: this.verboseLogging,
			log: (source, map) => eventLog.log(source, map),
			newPage: async () => (await context()).newPage(),
			urlVisited: (url) => this.urlVisited(url),
			addScreenshot: (name, png) => this.screenshots.push({ name, png }),
			updatePlaceholder: (...a) => this.updatePlaceholder(...a),
			runnerDone: (runner) => this.runners.delete(runner),
		};
	}

	/**
	 * Tell the front-end control that a url needs to be visited. If there is a matching browser configuration
	 * element, this will execute automatically. If there is no matching element, the url is made available for
	 * user interaction.
	 */
	goToUrl(url: string, placeholder: string | null = null, method = "GET", delaySeconds = 0): void {
		if (this.hook) {
			this.startRunner({ url, tasks: [], hook: this.hook, placeholder, method, delaySeconds });
			return;
		}
		for (const commandsEl of this.browserCommands) {
			const commands = commandsEl as JsonObject;
			if (!simpleMatch(OIDFJSON.getString(commands["match"]), url)) {
				continue;
			}
			if ("match-limit" in commands) {
				const limit = OIDFJSON.getInt(commands["match-limit"]);
				if (limit <= 0) {
					continue;
				}
				commands["match-limit"] = limit - 1;
			}
			const tasks = (commands["tasks"] as JsonArray) ?? [];
			this.startRunner({ url, tasks, hook: null, placeholder, method, delaySeconds });
			return;
		}
		if (this.verboseLogging) {
			this.eventLog.log("BROWSER", "asking user to visit url, no automation for found: " + url);
		}
		// if we couldn't find a command for this URL, leave it up to the user to do something with it (this port has
		// no UI listing the urls, the test waits for a callback that never comes)
	}

	/** Tell the front end control that a url has been visited. */
	urlVisited(url: string): void {
		this.visited.push(url);
	}

	getVisited(): string[] {
		return this.visited;
	}

	runnersActive(): boolean {
		return this.runners.size > 0;
	}

	private startRunner(job: WebRunnerJob): void {
		const wr = new WebRunner(this.runnerContext, job);
		this.runners.add(wr);
		this.executionManager.runInBackground(() => wr.run(), "browser");
	}

	/** Publish the given page content to fulfill the placeholder. */
	private updatePlaceholder(
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
				this.eventLog.log("BROWSER", {
					msg: "Skipping optional placeholder update as placeholder not found.",
					placeholder,
				});
				return;
			}
			throw new TestFailureException(this.testId, "Couldn't find matched placeholder for uploading error screenshot.");
		}
		this.eventLog.log("BROWSER", { msg: "Updated placeholder from scripted browser", placeholder });
		if (this.imageService.getRemainingPlaceholders(this.testId, true).length === 0) {
			this.eventLog.log("BROWSER", { msg: "All placeholders filled by scripted browser" });
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

interface WebRunnerJob {
	url: string;
	tasks: JsonArray;
	hook: BrowserHook | null;
	placeholder: string | null;
	method: string;
	delaySeconds: number;
}

/**
 * Port of BrowserControl.WebRunner: acts as the browser and allows goToUrl to return before the page gets hit.
 */
class WebRunner {
	private readonly ctx: RunnerContext;
	private readonly job: WebRunnerJob;
	private page: Page | null = null;
	private lastResponseCode: number | null = null;
	private lastResponseContentType: string | null = null;
	private lastResponseContent: string | null = null;

	constructor(ctx: RunnerContext, job: WebRunnerJob) {
		this.ctx = ctx;
		this.job = job;
	}

	private currentUrl(): string {
		return this.page?.url() ?? "";
	}

	private log(map: LogArgs): void {
		this.ctx.log("WebRunner", map);
	}

	async run(): Promise<string> {
		const { url, method, hook, placeholder } = this.job;
		try {
			if (this.job.delaySeconds > 0) {
				await sleep(this.job.delaySeconds * 1000);
			}
			this.page = await this.ctx.newPage();
			const page = this.page;
			if (this.ctx.verbose) {
				this.logBrowserEvents(page);
			}

			// Consider this URL visited. Java records the visit after driver.get() returns; a user-driven browser
			// (urlVisited() from the UI) records it before the implementation under test redirects anywhere, which is what
			// e.g. oidcc-client-test-3rd-party-init-login checks for when the authorization request arrives, so the visit
			// is recorded when the navigation starts.
			this.ctx.urlVisited(url);

			await this.recordResponse(method === "POST" ? await this.post(page) : await this.get(page));
			this.log({
				msg: "Scripted browser HTTP response",
				http: "response",
				response_status_code: this.lastResponseCode,
				response_status_text: this.status(),
				response_content_type: this.lastResponseContentType,
				response_content: this.lastResponseContent,
			});

			if (hook) {
				await hook({
					page,
					url,
					method,
					placeholder,
					log: (msg, extra) => this.log({ msg, browser: "hook", ...extra }),
				});
				if (placeholder) {
					await this.fillPlaceholder(null, true);
				}
				return "web runner exited";
			}

			for (const task of this.job.tasks) {
				await this.runTask(task as JsonObject);
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
					this.ctx.addScreenshot("webrunner-failure", screenshot);
				}
			} catch {
				// ignore
			}
			this.log(
				ex(e, {
					msg: err.message,
					page_source: pageSource,
					url: currentUrl,
					content_type: this.lastResponseContentType,
					result: ConditionResult.FAILURE,
					img: screenshot ? "data:image/png;base64," + screenshot.toString("base64") : undefined,
				}),
			);
			const testId = this.ctx.testId;
			if (e instanceof TestFailureException) {
				throw new TestFailureException(testId, "Web Runner Exception: " + err.message, e.cause);
			}
			throw new TestFailureException(testId, "Web Runner Exception: " + err.message, e);
		} finally {
			this.ctx.runnerDone(this);
			try {
				await this.page?.close();
			} catch {
				// ignore
			}
		}
	}

	private logBrowserEvents(page: Page): void {
		page.on("request", (req) => {
			this.log({
				msg: "Request " + req.method() + " " + req.url(),
				headers: req.headers(),
				body: req.postData(),
				result: ConditionResult.INFO,
			});
		});
		page.on("response", (res) => {
			const status = res.status();
			const msg =
				status === 302
					? `Redirect ${status} ${res.statusText()} to ${res.headers()["location"]} from ${res.request().method()} ${res.url()}`
					: `Response ${status} ${res.statusText()} ${res.request().method()} ${res.url()}`;
			this.log({ msg, headers: res.headers(), result: ConditionResult.INFO });
		});
		page.on("console", (m) => this.ctx.log("BROWSER", String(m.text())));
		page.on("pageerror", (e) =>
			this.ctx.log("BROWSER", { msg: "Error during JavaScript execution", detail: String(e) }),
		);
	}

	/** do the actual HTTP GET */
	private async get(page: Page): Promise<PageResponse | null> {
		const { url, method } = this.job;
		this.log({
			msg: "Scripted browser HTTP request",
			http: "request",
			request_uri: url,
			request_method: method,
			browser: "goToUrl",
		});
		return page.goto(url, { waitUntil: "load", timeout: 60_000 });
	}

	/** do the actual HTTP POST via an auto-submitting form, so the browser performs a real navigation */
	private async post(page: Page): Promise<PageResponse | null> {
		const formUrl = new URL(this.job.url);
		const params = formUrl.search.startsWith("?") ? formUrl.search.substring(1) : formUrl.search;
		formUrl.search = "";
		const urlWithoutQuery = formUrl.toString();
		this.log({
			msg: "Scripted browser HTTP request",
			http: "request",
			request_uri: urlWithoutQuery,
			parameters: params,
			request_method: this.job.method,
			browser: "goToUrl",
		});
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
		return responsePromise;
	}

	private async runTask(currentTask: JsonObject): Promise<void> {
		if (currentTask["task"] == null) {
			throw new TestFailureException(this.ctx.testId, "Invalid Task Definition: no 'task' property");
		}
		const taskName = OIDFJSON.getString(currentTask["task"]);
		// default to matching any URL
		const expectedUrlMatcher = "match" in currentTask ? OIDFJSON.getString(currentTask["match"]) : "*";

		if (expectedUrlMatcher && !simpleMatch(expectedUrlMatcher, this.currentUrl())) {
			if ("optional" in currentTask && OIDFJSON.getBoolean(currentTask["optional"])) {
				this.log({
					msg: "Skipping optional task due to URL mismatch",
					match: expectedUrlMatcher,
					url: this.currentUrl(),
					browser: "skip",
					task: taskName,
					commands: currentTask["commands"],
				});
				return;
			}
			this.log({
				msg: "Unexpected URL for non-optional task",
				match: expectedUrlMatcher,
				url: this.currentUrl(),
				result: ConditionResult.FAILURE,
				task: taskName,
				commands: currentTask["commands"],
			});
			throw new TestFailureException(this.ctx.testId, "WebRunner unexpected url for task: " + taskName);
		}

		const commands = currentTask["commands"];
		if (commands != null && isJsonArray(commands)) {
			// wait for webpage to finish loading
			try {
				await (this.page as Page).waitForLoadState("load", { timeout: 10_000 });
			} catch (e) {
				this.ctx.log("BROWSER", ex(e, { msg: "Timeout waiting for page to load" }));
			}
			for (const command of commands) {
				await this.doCommand(command as JsonArray, taskName);
			}
		}

		await this.recordResponse(null);
		this.log({
			msg: "Completed processing of webpage",
			match: expectedUrlMatcher,
			url: this.currentUrl(),
			browser: "complete",
			task: taskName,
			result: ConditionResult.INFO,
			response_status_code: this.lastResponseCode,
			response_status_text: this.status(),
		});
	}

	private async recordResponse(response: PageResponse | null): Promise<void> {
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
			this.ctx.addScreenshot("placeholder-" + (this.job.placeholder ?? "none"), screenshot);
		}
		this.ctx.updatePlaceholder(
			this.job.placeholder,
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
		const testId = this.ctx.testId;
		const page = this.page as Page;
		const commandString = OIDFJSON.getString(command[0]);
		if (!commandString) {
			throw new TestFailureException(testId, "Invalid Command: " + commandString);
		}
		const elementType = OIDFJSON.getString(command[1]);
		const target = OIDFJSON.getString(command[2]);
		/** Log a step of this command: the fields every command logs, `extra`, then the result (unless `extra` placed it) */
		const logStep = (msg: string, extra: LogArgs = {}) =>
			this.log({
				msg,
				url: this.currentUrl(),
				browser: commandString,
				task: taskName,
				element_type: elementType,
				target,
				...extra,
				result: ConditionResult.INFO,
			});

		switch (commandString.toLowerCase()) {
			case "click": {
				// ["click", "id" or "name", "id_or_name", "optional"]
				logStep("Clicking an element");
				const locator = await this.locate(elementType, target, command[3], () =>
					logStep("Element not found, skipping as 'click' command is marked 'optional'"),
				);
				if (locator) {
					const navigation = page.waitForNavigation({ timeout: 10_000 }).catch(() => null);
					await locator.click({ timeout: 10_000 });
					await navigation;
					await page.waitForLoadState("load", { timeout: 10_000 }).catch(() => {});
				}
				return;
			}
			case "text": {
				// ["text", "id" or "name", "id_or_name", "text_to_enter", "optional"]
				const value = OIDFJSON.getString(command[3]);
				logStep("Entering text", { value });
				const locator = await this.locate(elementType, target, command[4], () =>
					logStep("Element not found, skipping as 'text' command is marked 'optional'", { value }),
				);
				await locator?.fill(value, { timeout: 10_000 });
				return;
			}
			case "wait":
				return this.wait(command, elementType, target, logStep);
			case "wait-element-invisible":
				return this.waitForElement(
					command,
					elementType,
					target,
					"hidden",
					"Timed out waiting for element to become invisible: ",
				);
			case "wait-element-visible":
				return this.waitForElement(
					command,
					elementType,
					target,
					"visible",
					"Timed out waiting for element visibility: ",
				);
			default:
				throw new TestFailureException(testId, "Invalid Command: " + commandString);
		}
	}

	/**
	 * The first element matching, or null when there is none and the command is marked "optional" (after `skipped`
	 * logged that).
	 */
	private async locate(
		elementType: string,
		target: string,
		optionalArg: JsonValue | undefined,
		skipped: () => void,
	): Promise<Locator | null> {
		const locator = this.getSelector(elementType, target).first();
		const optional = optionalArg === undefined ? null : OIDFJSON.getString(optionalArg);
		if ((await locator.count()) > 0) {
			return locator;
		}
		if (optional === "optional") {
			skipped();
			return null;
		}
		throw new TestFailureException(this.ctx.testId, `Unable to locate element: ${elementType} '${target}'`);
	}

	/** ["wait","match" or "contains", "urlmatch_or_contains_string", timeout_in_seconds, regexp?, action?] */
	private async wait(
		command: JsonArray,
		elementType: string,
		target: string,
		logStep: (msg: string, extra: LogArgs) => void,
	): Promise<void> {
		const page = this.page as Page;
		const timeoutSeconds = OIDFJSON.getInt(command[3]);
		const regexp = command.length >= 5 ? OIDFJSON.getString(command[4]) : null;
		const action = command.length >= 6 ? OIDFJSON.getString(command[5]) : null;
		if (action && action !== "update-image-placeholder-optional" && action !== "update-image-placeholder") {
			throw new TestFailureException(this.ctx.testId, "Invalid action: " + action);
		}
		logStep("Waiting", { seconds: timeoutSeconds, result: ConditionResult.INFO, regexp, action });
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
				if (action) {
					await this.fillPlaceholder(regexp, action === "update-image-placeholder-optional");
				}
			} else {
				await this.getSelector(elementType, target).first().waitFor({ state: "attached", timeout });
			}
		} catch {
			throw new TestFailureException(this.ctx.testId, "Timed out waiting: " + JSON.stringify(command));
		}
	}

	/** ["wait-element-visible" or "wait-element-invisible", selector type, selector, timeout_in_seconds] */
	private async waitForElement(
		command: JsonArray,
		elementType: string,
		target: string,
		state: "visible" | "hidden",
		failure: string,
	): Promise<void> {
		const timeoutSeconds = OIDFJSON.getInt(command[3]);
		try {
			await this.getSelector(elementType, target)
				.first()
				.waitFor({ state, timeout: timeoutSeconds * 1000 });
		} catch {
			throw new TestFailureException(this.ctx.testId, failure + JSON.stringify(command));
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
				throw new TestFailureException(this.ctx.testId, "Invalid Command Selector: Type: " + type + " Value: " + value);
		}
	}
}

function escapeAttr(s: string): string {
	return s.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;");
}
