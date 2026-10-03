/**
 * The scripted browser (upstream frontchannel/BrowserControl + WebRunner, on Playwright instead of HtmlUnit).
 *
 * The configuration's `browser` is either upstream's JSON automation:
 *
 *   "browser": [
 *     { "match": "https://op.example.com/authorize*", "match-limit": 1,
 *       "tasks": [
 *         { "task": "Login", "match": "https://op.example.com/login*", "optional": true,
 *           "commands": [["text", "id", "username", "user"], ["click", "name", "submit"], ["wait", "contains", "callback", 10]] },
 *         { "task": "Verify Complete", "match": "*callback*", "commands": [["wait", "id", "submission_complete", 10]] } ] } ]
 *
 * (commands click, text, wait, wait-element-visible, wait-element-invisible; selectors id, name, xpath, css, class;
 * `wait` with a regexp and "update-image-placeholder[-optional]" fills a placeholder with a screenshot), or, in a
 * .ts config, a {@link BrowserHook} function that drives the page itself.
 *
 *   const browser = createBrowser({ context, automation: config.browser, log });
 *   await browser.visit(url);                 // resolves when the matching tasks ran, rejects when one failed
 *   await browser.visit(url, { method: "POST" });   // POST: the query becomes an auto-submitted form
 */
import type { BrowserContext, Locator, Page, Response as PageResponse } from "@playwright/test";
import { errorFields } from "./conditions.ts";
import type { EventLog, LogFields } from "./log.ts";

/** The alternative to the JSON automation: drive the OP's pages until the redirect back to the suite completes */
export type BrowserHook = (ctx: {
	page: Page;
	url: string;
	method: string;
	placeholder: string | null;
	log: (msg: string, extra?: Record<string, unknown>) => void;
}) => Promise<void>;

type Json = string | number | boolean | null | Json[] | { [k: string]: Json };
export type BrowserAutomation = Json[] | BrowserHook;

export interface BrowserOptions {
	context: BrowserContext;
	automation?: BrowserAutomation | null;
	log: EventLog;
	/** config `browser_verbose`: log every browser request/response/console message */
	verbose?: boolean;
	/** Called with every screenshot taken (failures, placeholders) */
	onScreenshot?: (name: string, png: Buffer) => void;
}

export interface VisitOptions {
	method?: "GET" | "POST";
	/** The REVIEW entry an "update-image-placeholder" wait (or a hook run) fills with a screenshot */
	placeholder?: string | null;
}

export interface Browser {
	/**
	 * Visits `url` and runs the automation that matches it. Resolves when its tasks completed; rejects (after
	 * logging a FAILURE entry with a screenshot) when a task failed. Without matching automation the page is opened
	 * and left to the user (useful with --headed) and the call resolves immediately.
	 */
	visit(url: string, opts?: VisitOptions): Promise<void>;
	/** The URLs visited, recorded when the navigation starts */
	readonly visited: string[];
}

export class BrowserError extends Error {
	override name = "BrowserError";
}

export function createBrowser(opts: BrowserOptions): Browser {
	const visited: string[] = [];
	const automation = opts.automation ?? [];
	return {
		visited,
		async visit(url, { method = "GET", placeholder = null } = {}) {
			if (typeof automation === "function") {
				return run(opts, { url, method, placeholder, tasks: [], hook: automation }, visited);
			}
			for (const entry of automation) {
				const commands = entry as { [k: string]: Json };
				if (!simpleMatch(String(commands["match"] ?? ""), url)) {
					continue;
				}
				if ("match-limit" in commands) {
					const limit = Number(commands["match-limit"]);
					if (limit <= 0) {
						continue;
					}
					commands["match-limit"] = limit - 1;
				}
				const tasks = (commands["tasks"] as Json[] | undefined) ?? [];
				return run(opts, { url, method, placeholder, tasks, hook: null }, visited);
			}
			opts.log.log("BROWSER", { msg: "asking user to visit url, no automation for found: " + url });
			visited.push(url);
			const page = await opts.context.newPage();
			void page.goto(url).catch(() => {});
		},
	};
}

/**
 * Spring's PatternMatchUtils.simpleMatch: "xxx*", "*xxx", "*xxx*" and "xxx*yyy" (any number of parts), or
 * equality.
 */
export function simpleMatch(pattern: string | null, str: string | null): boolean {
	if (pattern == null || str == null) {
		return false;
	}
	const parts = pattern.split("*");
	if (parts.length === 1) {
		return pattern === str;
	}
	return new RegExp("^" + parts.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$", "s").test(str);
}

interface Job {
	url: string;
	method: string;
	placeholder: string | null;
	tasks: Json[];
	hook: BrowserHook | null;
}

/** Upstream WebRunner.run(): one page, the tasks in order, a FAILURE entry with screenshot when anything fails */
async function run(opts: BrowserOptions, job: Job, visited: string[]): Promise<void> {
	const state: RunState = { opts, job, page: null, lastStatus: null, lastContentType: null, lastContent: null };
	try {
		const page = await opts.context.newPage();
		state.page = page;
		if (opts.verbose) {
			logBrowserEvents(state, page);
		}
		// recorded when the navigation starts (a user's browser reports the visit before the implementation under test
		// redirects anywhere, which e.g. oidcc-client-test-3rd-party-init-login relies on)
		visited.push(job.url);
		await recordResponse(state, job.method === "POST" ? await post(state, page) : await get(state, page));
		webRunnerLog(state, {
			msg: "Scripted browser HTTP response",
			http: "response",
			response_status_code: state.lastStatus,
			response_status_text: statusText(state),
			response_content_type: state.lastContentType,
			response_content: state.lastContent,
		});
		if (job.hook) {
			await job.hook({
				page,
				url: job.url,
				method: job.method,
				placeholder: job.placeholder,
				log: (msg, extra) => webRunnerLog(state, { msg, browser: "hook", ...extra }),
			});
			if (job.placeholder) {
				await fillPlaceholder(state, null, true);
			}
			return;
		}
		for (const task of job.tasks) {
			await runTask(state, task as { [k: string]: Json });
		}
	} catch (e) {
		const err = e as Error;
		let pageSource: string | null = null;
		let currentUrl: string | null = null;
		let screenshot: Buffer | undefined;
		try {
			if (state.page && !state.page.isClosed()) {
				currentUrl = state.page.url();
				pageSource = await state.page.content();
				screenshot = await state.page.screenshot({ fullPage: true });
				opts.onScreenshot?.("webrunner-failure", screenshot);
			}
		} catch {
			// the page is gone
		}
		webRunnerLog(state, {
			...errorFields(e),
			msg: err.message,
			page_source: pageSource,
			url: currentUrl,
			content_type: state.lastContentType,
			result: "FAILURE",
			img: screenshot ? "data:image/png;base64," + screenshot.toString("base64") : undefined,
		});
		throw new BrowserError("Web Runner Exception: " + err.message, { cause: e });
	} finally {
		await state.page?.close().catch(() => {});
	}
}

interface RunState {
	opts: BrowserOptions;
	job: Job;
	page: Page | null;
	lastStatus: number | null;
	lastContentType: string | null;
	lastContent: string | null;
}

function webRunnerLog(state: RunState, fields: LogFields): void {
	state.opts.log.log("WebRunner", fields);
}

function currentUrl(state: RunState): string {
	return state.page?.url() ?? "";
}

function statusText(state: RunState): string {
	return state.lastStatus == null ? "" : `${state.lastStatus}-`;
}

function logBrowserEvents(state: RunState, page: Page): void {
	page.on("request", (req) =>
		webRunnerLog(state, {
			msg: "Request " + req.method() + " " + req.url(),
			headers: req.headers(),
			body: req.postData(),
			result: "INFO",
		}),
	);
	page.on("response", (res) => {
		const status = res.status();
		const msg =
			status === 302
				? `Redirect ${status} ${res.statusText()} to ${res.headers()["location"]} from ${res.request().method()} ${res.url()}`
				: `Response ${status} ${res.statusText()} ${res.request().method()} ${res.url()}`;
		webRunnerLog(state, { msg, headers: res.headers(), result: "INFO" });
	});
	page.on("console", (m) => state.opts.log.log("BROWSER", String(m.text())));
	page.on("pageerror", (e) =>
		state.opts.log.log("BROWSER", { msg: "Error during JavaScript execution", detail: String(e) }),
	);
}

async function get(state: RunState, page: Page): Promise<PageResponse | null> {
	webRunnerLog(state, {
		msg: "Scripted browser HTTP request",
		http: "request",
		request_uri: state.job.url,
		request_method: state.job.method,
		browser: "goToUrl",
	});
	return page.goto(state.job.url, { waitUntil: "load", timeout: 60_000 });
}

/** POST via an auto-submitting form, so the browser performs a real top-level navigation */
async function post(state: RunState, page: Page): Promise<PageResponse | null> {
	const formUrl = new URL(state.job.url);
	const params = formUrl.search.startsWith("?") ? formUrl.search.substring(1) : formUrl.search;
	formUrl.search = "";
	const action = formUrl.toString();
	webRunnerLog(state, {
		msg: "Scripted browser HTTP request",
		http: "request",
		request_uri: action,
		parameters: params,
		request_method: state.job.method,
		browser: "goToUrl",
	});
	const inputs = [...new URLSearchParams(params).entries()]
		.map(([k, v]) => `<input type="hidden" name="${escapeAttr(k)}" value="${escapeAttr(v)}">`)
		.join("");
	await page.setContent(
		`<html><body><form id="f" method="post" action="${escapeAttr(action)}">${inputs}</form></body></html>`,
	);
	// listen before submitting so that an immediate response is not missed
	const response = page
		.waitForResponse((r) => r.request().isNavigationRequest() && r.url().startsWith(action), { timeout: 60_000 })
		.catch(() => null);
	const navigated = page.waitForURL((u) => u.protocol !== "about:", { timeout: 60_000, waitUntil: "load" });
	await page.evaluate('document.getElementById("f").submit()');
	await navigated;
	return response;
}

async function recordResponse(state: RunState, response: PageResponse | null): Promise<void> {
	if (response) {
		state.lastStatus = response.status();
		state.lastContentType = response.headers()["content-type"] ?? null;
	}
	try {
		state.lastContent = state.page && !state.page.isClosed() ? await state.page.content() : null;
	} catch {
		state.lastContent = null;
	}
}

async function runTask(state: RunState, task: { [k: string]: Json }): Promise<void> {
	if (task["task"] == null) {
		throw new BrowserError("Invalid Task Definition: no 'task' property");
	}
	const taskName = String(task["task"]);
	const expected = "match" in task ? String(task["match"]) : "*";
	if (expected && !simpleMatch(expected, currentUrl(state))) {
		if (task["optional"] === true) {
			webRunnerLog(state, {
				msg: "Skipping optional task due to URL mismatch",
				match: expected,
				url: currentUrl(state),
				browser: "skip",
				task: taskName,
				commands: task["commands"],
			});
			return;
		}
		webRunnerLog(state, {
			msg: "Unexpected URL for non-optional task",
			match: expected,
			url: currentUrl(state),
			result: "FAILURE",
			task: taskName,
			commands: task["commands"],
		});
		throw new BrowserError("WebRunner unexpected url for task: " + taskName);
	}
	const commands = task["commands"];
	if (Array.isArray(commands)) {
		try {
			await (state.page as Page).waitForLoadState("load", { timeout: 10_000 });
		} catch (e) {
			state.opts.log.log("BROWSER", { ...errorFields(e), msg: "Timeout waiting for page to load" });
		}
		for (const command of commands) {
			await doCommand(state, command as Json[], taskName);
		}
	}
	await recordResponse(state, null);
	webRunnerLog(state, {
		msg: "Completed processing of webpage",
		match: expected,
		url: currentUrl(state),
		browser: "complete",
		task: taskName,
		result: "INFO",
		response_status_code: state.lastStatus,
		response_status_text: statusText(state),
	});
}

/** ["click"|"text"|"wait"|"wait-element-visible"|"wait-element-invisible", selector type, selector, ...] */
async function doCommand(state: RunState, command: Json[], taskName: string): Promise<void> {
	const page = state.page as Page;
	const name = String(command[0] ?? "");
	if (!name) {
		throw new BrowserError("Invalid Command: " + name);
	}
	const elementType = String(command[1]);
	const target = String(command[2]);
	const logStep = (msg: string, extra: LogFields = {}) =>
		webRunnerLog(state, {
			msg,
			url: currentUrl(state),
			browser: name,
			task: taskName,
			element_type: elementType,
			target,
			...extra,
			result: "INFO",
		});

	switch (name.toLowerCase()) {
		case "click": {
			logStep("Clicking an element");
			const locator = await locate(page, elementType, target, command[3], () =>
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
			const value = String(command[3]);
			logStep("Entering text", { value });
			const locator = await locate(page, elementType, target, command[4], () =>
				logStep("Element not found, skipping as 'text' command is marked 'optional'", { value }),
			);
			await locator?.fill(value, { timeout: 10_000 });
			return;
		}
		case "wait":
			return wait(state, command, elementType, target, logStep);
		case "wait-element-invisible":
			return waitForElement(
				page,
				command,
				elementType,
				target,
				"hidden",
				"Timed out waiting for element to become invisible: ",
			);
		case "wait-element-visible":
			return waitForElement(
				page,
				command,
				elementType,
				target,
				"visible",
				"Timed out waiting for element visibility: ",
			);
		default:
			throw new BrowserError("Invalid Command: " + name);
	}
}

async function locate(
	page: Page,
	elementType: string,
	target: string,
	optional: Json | undefined,
	skipped: () => void,
): Promise<Locator | null> {
	const locator = selector(page, elementType, target).first();
	if ((await locator.count()) > 0) {
		return locator;
	}
	if (optional === "optional") {
		skipped();
		return null;
	}
	throw new BrowserError(`Unable to locate element: ${elementType} '${target}'`);
}

/** ["wait", "match"|"contains"|selector type, url-or-selector, timeout seconds, regexp?, placeholder action?] */
async function wait(
	state: RunState,
	command: Json[],
	elementType: string,
	target: string,
	logStep: (msg: string, extra: LogFields) => void,
): Promise<void> {
	const page = state.page as Page;
	const timeoutSeconds = Number(command[3]);
	const regexp = command.length >= 5 ? String(command[4]) : null;
	const action = command.length >= 6 ? String(command[5]) : null;
	if (action && action !== "update-image-placeholder-optional" && action !== "update-image-placeholder") {
		throw new BrowserError("Invalid action: " + action);
	}
	logStep("Waiting", { seconds: timeoutSeconds, result: "INFO", regexp, action });
	const timeout = timeoutSeconds * 1000;
	try {
		if (elementType.toLowerCase() === "contains") {
			await page.waitForURL((u) => u.toString().includes(target), { timeout, waitUntil: "commit" });
		} else if (elementType.toLowerCase() === "match") {
			const re = new RegExp(target);
			await page.waitForURL((u) => re.test(u.toString()), { timeout, waitUntil: "commit" });
		} else if (regexp) {
			const re = new RegExp(regexp);
			// the first element the selector names must contain text matching the regexp
			await selector(page, elementType, target).first().filter({ hasText: re }).waitFor({ state: "attached", timeout });
			if (action) {
				await fillPlaceholder(state, regexp, action === "update-image-placeholder-optional");
			}
		} else {
			await selector(page, elementType, target).first().waitFor({ state: "attached", timeout });
		}
	} catch (e) {
		if (e instanceof BrowserError) {
			throw e;
		}
		throw new BrowserError("Timed out waiting: " + JSON.stringify(command));
	}
}

async function waitForElement(
	page: Page,
	command: Json[],
	elementType: string,
	target: string,
	visibility: "visible" | "hidden",
	failure: string,
): Promise<void> {
	try {
		await selector(page, elementType, target)
			.first()
			.waitFor({ state: visibility, timeout: Number(command[3]) * 1000 });
	} catch {
		throw new BrowserError(failure + JSON.stringify(command));
	}
}

/** Fills the job's placeholder (a REVIEW entry) with a screenshot of the page (upstream ImageService) */
async function fillPlaceholder(state: RunState, regexp: string | null, optional: boolean): Promise<void> {
	const page = state.page as Page;
	const log = state.opts.log;
	const screenshot = await page.screenshot({ fullPage: true }).catch(() => undefined);
	if (screenshot) {
		state.opts.onScreenshot?.("placeholder-" + (state.job.placeholder ?? "none"), screenshot);
	}
	const update: LogFields = {
		page_source: await page.content(),
		content_type: state.lastContentType,
		matched_regexp: regexp,
		img: screenshot ? "data:image/png;base64," + screenshot.toString("base64") : undefined,
	};
	const placeholder = state.job.placeholder;
	if (placeholder == null || log.fillPlaceholder(placeholder, update) == null) {
		if (optional) {
			log.log("BROWSER", { msg: "Skipping optional placeholder update as placeholder not found.", placeholder });
			return;
		}
		throw new BrowserError("Couldn't find matched placeholder for uploading error screenshot.");
	}
	log.log("BROWSER", { msg: "Updated placeholder from scripted browser", placeholder });
	if (log.remainingPlaceholders().length === 0) {
		log.log("BROWSER", { msg: "All placeholders filled by scripted browser" });
	}
}

/** id, name, xpath, css and class selectors (upstream BrowserControl.getSelector) */
function selector(page: Page, type: string, value: string): Locator {
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
			throw new BrowserError("Invalid Command Selector: Type: " + type + " Value: " + value);
	}
}

function escapeAttr(s: string): string {
	return s.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;");
}
