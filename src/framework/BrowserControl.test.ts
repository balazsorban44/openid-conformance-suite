import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, snapshot, test } from "node:test";
import { chromium, type Browser } from "@playwright/test";
import { BrowserControl, simpleMatch } from "./BrowserControl.ts";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";
import type { TestInterruptedException } from "./exceptions.ts";
import { TestExecutionManager } from "./execution.ts";
import { ImageService } from "./ImageService.ts";
import type { JsonObject } from "./json.ts";

test("simpleMatch follows Spring PatternMatchUtils", () => {
	assert.ok(simpleMatch("https://op/authorize*", "https://op/authorize?x=1"));
	assert.ok(simpleMatch("*/callback*", "http://localhost:1234/test/a/x/callback?code=1"));
	assert.ok(simpleMatch("*", "anything"));
	assert.ok(simpleMatch("exact", "exact"));
	assert.ok(!simpleMatch("exact", "exactly"));
	assert.ok(simpleMatch("a*b*c", "aXXbYYc"));
	assert.ok(!simpleMatch("a*b*c", "aXXbYY"));
	assert.ok(!simpleMatch(null, "x"));
});

test("goToUrl without matching automation leaves the url to the user", () => {
	const log = new TestInstanceEventLog("bc0");
	const exec = new TestExecutionManager("bc0", { onError: async () => {}, afterTask: () => {} });
	const bc = new BrowserControl(
		{ browser: [{ match: "https://other/*", tasks: [] }], browser_verbose: true },
		"bc0",
		log,
		exec,
		new ImageService(log),
		() => Promise.reject(new Error("no browser")),
	);
	bc.goToUrl("https://op/authorize?x=1");
	assert.equal(bc.runnersActive(), false);
	assert.deepEqual(bc.getVisited(), []);
	assert.deepEqual(
		log.entries.map((e) => [e.src, e["msg"]]),
		[["BROWSER", "asking user to visit url, no automation for found: https://op/authorize?x=1"]],
	);
});

// --- the scripted browser against a real Chromium (skipped when Playwright's Chromium is not installed) ---

const noChromium = !existsSync(chromium.executablePath()) && "Playwright Chromium is not installed";

const pages: Record<string, string> = {
	"/start": `<html><body><h1>Login</h1><form action="/callback" method="get">
<input id="username" name="username"><input name="password" type="password">
<button id="submit" type="submit">go</button></form><p id="hiddenThing" style="display:none">x</p></body></html>`,
	"/callback": `<html><body><p id="result">done 42</p><span id="submission_complete"></span></body></html>`,
	"/slow": `<html><body><p id="later"></p><script>setTimeout(() => document.getElementById("later").textContent = "now visible", 300)</script></body></html>`,
};

let server: Server;
let base = "";
let browser: Browser;
const received: { method: string; url: string; body: string; visitedBefore: boolean }[] = [];
let currentControl: BrowserControl | null = null;

before(async () => {
	if (noChromium) {
		return;
	}
	server = createServer((req, res) => {
		let body = "";
		req.on("data", (c) => (body += c));
		req.on("end", () => {
			const url = new URL(req.url ?? "/", base);
			received.push({
				method: req.method ?? "",
				url: url.pathname + url.search,
				body,
				visitedBefore: currentControl?.getVisited().some((v) => v.startsWith(base + url.pathname)) ?? false,
			});
			const page =
				url.pathname === "/post" ? `<html><body><p id="posted">${body}</p></body></html>` : pages[url.pathname];
			res.writeHead(page ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
			res.end(page ?? "<html><body>not found</body></html>");
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	browser = await chromium.launch();
});

after(async () => {
	await browser?.close();
	server?.close();
});

interface Run {
	log: TestInstanceEventLog;
	bc: BrowserControl;
	errors: [TestInterruptedException, string][];
	normalized: () => Record<string, unknown>[];
}

/** Run goToUrl() calls to completion and return the log (normalized for snapshots: no ids, times, ports or page dumps) */
async function run(
	config: JsonObject | Record<string, unknown>,
	calls: (bc: BrowserControl, log: TestInstanceEventLog) => void,
): Promise<Run> {
	const log = new TestInstanceEventLog("bc");
	const errors: [TestInterruptedException, string][] = [];
	const exec = new TestExecutionManager("bc", {
		onError: async (e, source) => {
			errors.push([e, source]);
		},
		afterTask: () => {},
	});
	const context = await browser.newContext();
	const bc = new BrowserControl(config as JsonObject, "bc", log, exec, new ImageService(log), async () => context);
	currentControl = bc;
	try {
		calls(bc, log);
		await exec.drain();
	} finally {
		await context.close();
		currentControl = null;
	}
	assert.equal(bc.runnersActive(), false);
	const normalized = () =>
		log.entries.map((e: LogEntry) => {
			const { _id, testId, time, seq, ...rest } = e;
			assert.equal(_id, `bc-${seq}`);
			assert.equal(testId, "bc");
			assert.equal(typeof time, "number");
			return JSON.parse(
				JSON.stringify(rest, (k, v) => {
					if (["page_source", "response_content"].includes(k) && typeof v === "string") {
						return "[html]";
					}
					if (k === "img" && typeof v === "string") {
						return v.startsWith("data:image/png;base64,") ? "[png]" : v;
					}
					if (k.endsWith("stacktrace")) {
						return "[stack]";
					}
					return typeof v === "string" ? v.replaceAll(base, "BASE") : v;
				}),
			) as Record<string, unknown>;
		});
	return { log, bc, errors, normalized };
}

snapshot.setDefaultSnapshotSerializers([(v) => JSON.stringify(v, null, "\t")]);

test(
	"scripted browser: tasks, commands, optional parts, placeholders and match-limit",
	{ skip: noChromium },
	async (t) => {
		received.length = 0;
		const r = await run(
			{
				browser: [
					{
						match: "*/start*",
						"match-limit": 1,
						tasks: [
							{
								task: "Login",
								match: "*/start*",
								commands: [
									["text", "id", "username", "user"],
									["text", "name", "nope", "x", "optional"],
									["click", "id", "nope", "optional"],
									["click", "id", "submit"],
								],
							},
							{ task: "Not this one", match: "*/elsewhere*", optional: true, commands: [["click", "id", "x"]] },
							{
								task: "Verify Complete",
								match: "*/callback*",
								commands: [
									["wait", "id", "result", 5, "done \\d+", "update-image-placeholder"],
									["wait", "contains", "callback", 5],
									["wait", "match", ".*callback.*", 5],
									["wait-element-visible", "id", "result", 5],
									["wait-element-invisible", "id", "absent", 5],
									["wait", "css", "#submission_complete", 5],
								],
							},
							{ task: "No commands" },
						],
					},
				],
			},
			(bc, log) => {
				log.log("SomeCondition", { msg: "placeholder", upload: "ph1" });
				bc.goToUrl(base + "/start?x=1", "ph1");
				// match-limit reached: left to the user
				bc.goToUrl(base + "/start?x=2");
			},
		);
		assert.deepEqual(r.errors, []);
		assert.deepEqual(
			received.map((x) => [x.method, x.url, x.visitedBefore]),
			[
				["GET", "/start?x=1", true],
				["GET", "/callback?username=user&password=", false],
			],
		);
		assert.deepEqual(r.bc.getVisited(), [base + "/start?x=1"]);
		const placeholder = r.log.entries[0];
		assert.deepEqual(Object.keys(placeholder).slice(5), [
			"msg",
			"upload",
			"page_source",
			"content_type",
			"matched_regexp",
			"img",
		]);
		assert.equal(placeholder["matched_regexp"], "done \\d+");
		assert.equal(placeholder["content_type"], "text/html; charset=utf-8");
		assert.ok(r.bc.screenshots.some((s) => s.name === "placeholder-ph1"));
		t.assert.snapshot(r.normalized());
	},
);

test("scripted browser: optional placeholder update without a placeholder", { skip: noChromium }, async (t) => {
	const r = await run(
		{
			browser: [
				{
					match: "*/callback*",
					tasks: [
						{
							task: "Verify",
							commands: [["wait", "id", "result", 5, "done", "update-image-placeholder-optional"]],
						},
					],
				},
			],
		},
		(bc) => bc.goToUrl(base + "/callback"),
	);
	assert.deepEqual(r.errors, []);
	t.assert.snapshot(r.normalized());
});

test("scripted browser: POST navigation goes through a form", { skip: noChromium }, async (t) => {
	received.length = 0;
	const r = await run(
		{
			browser: [
				{ match: "*/post*", tasks: [{ task: "Check", commands: [["wait", "id", "posted", 5, "a=1&b=x\\+y"]] }] },
			],
		},
		(bc) => bc.goToUrl(base + "/post?a=1&b=x+y", null, "POST"),
	);
	assert.deepEqual(r.errors, []);
	assert.deepEqual(
		received.map((x) => [x.method, x.url, x.body, x.visitedBefore]),
		[["POST", "/post", "a=1&b=x+y", true]],
	);
	t.assert.snapshot(r.normalized());
});

test("scripted browser: failures", { skip: noChromium }, async (t) => {
	const cases: [string, unknown[]][] = [
		["unexpected url", [{ task: "Wrong page", match: "*/elsewhere*", commands: [["click", "id", "x"]] }]],
		["invalid command", [{ task: "T", commands: [["dance", "id", "x"]] }]],
		["invalid selector", [{ task: "T", commands: [["click", "tag", "x"]] }]],
		["invalid action", [{ task: "T", commands: [["wait", "id", "result", 1, "x", "bogus"]] }]],
		["missing element", [{ task: "T", commands: [["text", "id", "nope", "v"]] }]],
		["wait timeout", [{ task: "T", commands: [["wait", "id", "result", 1, "never"]] }]],
		["visible timeout", [{ task: "T", commands: [["wait-element-visible", "id", "nope", 1]] }]],
		["invisible timeout", [{ task: "T", commands: [["wait-element-invisible", "id", "result", 1]] }]],
		["no task name", [{ match: "*" }]],
		[
			"placeholder required",
			[{ task: "T", commands: [["wait", "id", "result", 1, "done", "update-image-placeholder"]] }],
		],
	];
	const results: Record<string, unknown> = {};
	for (const [name, tasks] of cases) {
		const r = await run({ browser: [{ match: "*", tasks }] }, (bc) => bc.goToUrl(base + "/callback"));
		assert.equal(r.errors.length, 1, name);
		const [error, source] = r.errors[0];
		assert.equal(source, "browser");
		assert.equal(error.getTestId(), "bc");
		assert.ok(r.bc.screenshots.some((s) => s.name === "webrunner-failure"));
		results[name] = { error: [error.name, error.message], log: r.normalized() };
	}
	t.assert.snapshot(results);
});

test("scripted browser: a TypeScript hook drives the page", { skip: noChromium }, async (t) => {
	const r = await run(
		{
			browser: async (ctx: {
				page: import("@playwright/test").Page;
				url: string;
				method: string;
				placeholder: string | null;
				log: (msg: string, extra?: Record<string, unknown>) => void;
			}) => {
				await ctx.page.fill("#username", "u");
				ctx.log("filled", { field: "username", n: 1 });
				ctx.log("plain");
				assert.equal(ctx.method, "GET");
				assert.equal(ctx.placeholder, "ph");
				assert.equal(ctx.url, base + "/start");
			},
		},
		(bc, log) => {
			log.log("Cond", { msg: "p", upload: "ph" });
			bc.goToUrl(base + "/start", "ph");
		},
	);
	assert.deepEqual(r.errors, []);
	t.assert.snapshot(r.normalized());
});

test("scripted browser: verbose logging and a delayed start", { skip: noChromium }, async () => {
	const started = Date.now();
	const r = await run(
		{
			browser_verbose: true,
			browser: [{ match: "*/slow*", tasks: [{ task: "T", commands: [["wait", "id", "later", 5, "now"]] }] }],
		},
		(bc) => bc.goToUrl(base + "/slow", null, "GET", 1),
	);
	assert.ok(Date.now() - started >= 1000);
	assert.deepEqual(r.errors, []);
	const entries = r.normalized();
	const request = entries.find((e) => e["msg"] === "Request GET BASE/slow");
	assert.deepEqual(Object.keys(request ?? {}), ["src", "msg", "headers", "body", "result"]);
	assert.equal(request?.["src"], "WebRunner");
	assert.equal(request?.["result"], "INFO");
	const response = entries.find((e) => e["msg"] === "Response 200 OK GET BASE/slow");
	assert.deepEqual(Object.keys(response ?? {}), ["src", "msg", "headers", "result"]);
	assert.deepEqual(
		entries
			.filter((e) => e["src"] === "WebRunner" && !String(e["msg"]).match(/^(Request|Response) /))
			.map((e) => e["msg"]),
		["Scripted browser HTTP request", "Scripted browser HTTP response", "Waiting", "Completed processing of webpage"],
	);
});
