import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { AbstractCondition } from "./AbstractCondition.ts";
import { ConditionResult } from "./Condition.ts";
import type { LogArgs } from "./DataUtils.ts";
import { Environment } from "./Environment.ts";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";
import { addBodyProperty, HttpClient, HttpClientException, type HttpResponse } from "./http.ts";

/*
 * Pins the "HTTP request" / "HTTP response" log entries of HttpClient (LoggingRequestInterceptor upstream).
 */

let server: Server;
let base = "";
const seen: { method: string; url: string; headers: IncomingMessage["headers"]; body: string }[] = [];

before(async () => {
	server = createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (c: Buffer) => chunks.push(c));
		req.on("end", () => {
			seen.push({
				method: req.method ?? "",
				url: req.url ?? "",
				headers: req.headers,
				body: Buffer.concat(chunks).toString(),
			});
			const path = (req.url ?? "").split("?")[0];
			if (path === "/json") {
				res.setHeader("Set-Cookie", ["a=1", "b=2"]);
				res.writeHead(200, { "Content-Type": "application/json", "X-Custom": "yes" });
				res.end('{"ok":true}');
			} else if (path === "/redirect") {
				res.writeHead(302, { Location: "/json" });
				res.end();
			} else if (path === "/error") {
				res.writeHead(500, "Server Broke", { "Content-Type": "text/plain" });
				res.end("oops");
			} else {
				res.writeHead(404);
				res.end();
			}
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

function strip(e: LogEntry): LogArgs {
	const { _id, testId: _testId, time: _time, seq: _seq, ...rest } = e;
	// the date header changes every second
	const h = rest["response_headers"] as Record<string, unknown> | undefined;
	if (h) {
		assert.equal(typeof h["date"], "string");
		delete h["date"];
	}
	return rest;
}

function assertEntry(e: LogEntry, expected: LogArgs): void {
	const b = strip(e);
	assert.deepEqual(b, expected);
	assert.deepEqual(Object.keys(b), Object.keys(expected));
}

async function exchange(
	req: Parameters<HttpClient["exchange"]>[0],
	extra: Partial<ConstructorParameters<typeof HttpClient>[0]> = {},
): Promise<{ res: HttpResponse; log: TestInstanceEventLog }> {
	const log = new TestInstanceEventLog("tid");
	const client = new HttpClient({ source: "Caller", log, ...extra });
	try {
		return { res: await client.exchange(req), log };
	} finally {
		await client.close();
	}
}

test("GET: request and response entries", async () => {
	const { res, log } = await exchange({ url: base + "/json?x=1", headers: { Accept: "application/json" } });
	assert.equal(res.status, 200);
	assert.equal(res.body, '{"ok":true}');
	assert.equal(log.entries.length, 2);
	assertEntry(log.entries[0], {
		src: "Caller",
		request_uri: base + "/json?x=1",
		request_method: "GET",
		request_headers: {
			accept: "application/json",
			"accept-encoding": "identity",
			"user-agent": "openid-conformance-suite",
		},
		msg: "HTTP request",
		http: "request",
	});
	assertEntry(log.entries[1], {
		src: "Caller",
		response_status_code: "200",
		response_status_text: "OK",
		// undici's Headers is not the global Headers class, so mapToJsonObject takes the iterable branch: sorted
		// names, set-cookie values merged in place (one connection per call: "connection: close")
		response_headers: {
			connection: "close",
			"content-type": "application/json",
			"set-cookie": ["a=1", "b=2"],
			"transfer-encoding": "chunked",
			"x-custom": "yes",
		},
		response_body: '{"ok":true}',
		msg: "HTTP response",
		http: "response",
	});
});

test("POST bodies: form, JSON and string; mTLS config is logged", async () => {
	const form = await exchange(
		{ url: base + "/json", method: "POST", body: new URLSearchParams({ a: "1 2", b: "+" }) },
		{ mutualTls: { cert: "CERT", key: "KEY" } },
	);
	assertEntry(form.log.entries[0], {
		src: "Caller",
		request_uri: base + "/json",
		request_method: "POST",
		request_headers: {
			"accept-encoding": "identity",
			"content-length": "11",
			"content-type": "application/x-www-form-urlencoded;charset=UTF-8",
			"user-agent": "openid-conformance-suite",
		},
		request_body: "a=1+2&b=%2B",
		msg: "HTTP request",
		http: "request",
		request_mutual_tls: { cert: "CERT", key: "KEY" },
	});
	const json = await exchange({ url: base + "/json", method: "PUT", body: { k: ["v"] } });
	assert.equal((json.log.entries[0]["request_headers"] as LogArgs)["content-type"], "application/json");
	assert.equal(json.log.entries[0]["request_body"], '{"k":["v"]}');
	const str = await exchange({
		url: base + "/json",
		method: "POST",
		body: "raw",
		headers: { "content-type": "text/x" },
	});
	assert.equal((str.log.entries[0]["request_headers"] as LogArgs)["content-type"], "text/x");
	assert.equal(seen.at(-1)?.body, "raw");
});

test("redirects are not followed; 4xx/5xx do not throw; empty bodies", async () => {
	const redirect = await exchange({ url: base + "/redirect" });
	assert.equal(redirect.res.status, 302);
	assert.equal(redirect.res.headers.get("location"), "/json");
	assert.equal(redirect.log.entries.length, 2);
	assert.equal(redirect.log.entries[1]["response_status_code"], "302");
	assert.equal(redirect.log.entries[1]["response_status_text"], "Found");
	assert.equal(redirect.res.body, null);
	assert.equal(redirect.log.entries[1]["response_body"], "");

	const error = await exchange({ url: base + "/error" });
	assert.equal(error.res.status, 500);
	assert.equal(error.res.statusText, "Server Broke");
	assert.equal(error.log.entries[1]["response_status_code"], "500");
	assert.equal(error.log.entries[1]["response_status_text"], "Server Broke");
	assert.equal(error.log.entries[1]["response_body"], "oops");

	const missing = await exchange({ url: base + "/missing" });
	assert.equal(missing.res.status, 404);
});

test("network errors throw HttpClientException after logging the request", async () => {
	const closed = createServer();
	await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
	const port = (closed.address() as AddressInfo).port;
	await new Promise<void>((resolve) => closed.close(() => resolve()));
	const log = new TestInstanceEventLog("tid");
	const client = new HttpClient({ source: "Caller", log });
	const url = `http://127.0.0.1:${port}/x`;
	await assert.rejects(client.exchange({ url, method: "POST", body: "b" }), (e: unknown) => {
		assert.ok(e instanceof HttpClientException);
		assert.equal(e.name, "HttpClientException");
		assert.equal(e.message, `I/O error on POST request for "${url}": connect ECONNREFUSED 127.0.0.1:${port}`);
		return true;
	});
	await client.close();
	assert.deepEqual(
		log.entries.map((e) => e["msg"]),
		["HTTP request"],
	);
});

test("the test lock is released around the network call", async () => {
	const calls: string[] = [];
	const log = new TestInstanceEventLog("tid", (e) => calls.push(String(e["msg"])));
	const lockManager = {
		releaseLock: async () => void calls.push("release"),
		reacquireLock: async () => void calls.push("reacquire"),
		disable: () => {},
	};
	const client = new HttpClient({ source: "Caller", log, lockManager });
	await client.exchange({ url: base + "/json" });
	await client.close();
	assert.deepEqual(calls, ["HTTP request", "release", "reacquire", "HTTP response"]);
});

test("binary bodies are summarised", () => {
	const o: LogArgs = {};
	addBodyProperty(o, "response_body", new Uint8Array([0xff, 0x00, 0x41, 0x5c]));
	assert.deepEqual(o, {
		response_body_omitted: "binary content, 4 bytes - not shown (not valid UTF-8)",
		response_body_first_bytes: "\\xff\\x00A\\\\",
	});
	const c: LogArgs = {};
	addBodyProperty(c, "b", new TextEncoder().encode("ok\u0001"));
	assert.equal(
		c["b_omitted"],
		"binary content, 3 bytes - not shown (decodes as UTF-8 but contains control character U+0001 at character offset 2 (byte offset 2))",
	);
});

class CachedFetch extends AbstractCondition {
	url = "";
	override async evaluate(env: Environment): Promise<Environment> {
		for (let i = 0; i < 2; i++) {
			const client = await this.createRestTemplateWithCache(env);
			await client.exchange({ url: this.url });
			await client.close();
		}
		this.logSuccess("fetched");
		return env;
	}
}

test("createRestTemplateWithCache: the second fetch is logged as a cached response", async () => {
	const c = new CachedFetch();
	c.url = `${base}/json?cache=${Date.now()}`;
	const log = new TestInstanceEventLog("tid");
	c.setProperties("tid", log, ConditionResult.FAILURE, []);
	const env = new Environment();
	env.putObject("config", { options: { cache_external_metadata: true } });
	const hitsBefore = seen.length;
	await c.execute(env);
	assert.equal(seen.length, hitsBefore + 1);
	assert.deepEqual(
		log.entries.map((e) => [e.src, e["msg"], e["http"]]),
		[
			["CachedFetch", "HTTP request", "request"],
			["CachedFetch", "HTTP response", "response"],
			["CachedFetch", "HTTP request", "request"],
			["CachedFetch", "Using cached HTTP response", "response"],
			["CachedFetch", "fetched", undefined],
		],
	);
	const cached = strip(log.entries[3]);
	assert.deepEqual(Object.keys(cached), [
		"src",
		"response_status_code",
		"response_status_text",
		"response_headers",
		"response_body",
		"msg",
		"cache_age_seconds",
		"http",
	]);
	assert.equal(typeof cached["cache_age_seconds"], "number");
	assert.equal(cached["response_body"], '{"ok":true}');
});
