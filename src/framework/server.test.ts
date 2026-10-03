import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";
import { after, before, test } from "node:test";
import type { AbstractTestModule } from "./AbstractTestModule.ts";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";
import { TestFailureException, type TestInterruptedException } from "./exceptions.ts";
import type { JsonObject } from "./json.ts";
import { buildRequestParts, convertQueryStringParamsToMap, SuiteServer } from "./server.ts";
import type { HttpSession, IncomingHttpRequest } from "./TestModule.ts";

function fakeRequest(
	method: string,
	headers: Record<string, string | string[]>,
	socket: Record<string, unknown> = {},
): IncomingMessage {
	return { method, headers, socket } as unknown as IncomingMessage;
}

const tlsSocket = {
	encrypted: true,
	getCipher: () => ({ name: "TLS_AES_128_GCM_SHA256", standardName: "TLS_AES_128_GCM_SHA256", version: "TLSv1.3" }),
	getProtocol: () => "TLSv1.3",
};

test("convertQueryStringParamsToMap keeps order and duplicates", () => {
	assert.deepEqual(convertQueryStringParamsToMap(null), []);
	assert.deepEqual(convertQueryStringParamsToMap(""), []);
	assert.deepEqual(convertQueryStringParamsToMap("b=2&a=1&b=3&e=%20x+y"), [
		["b", "2"],
		["a", "1"],
		["b", "3"],
		["e", " x y"],
	]);
});

test("buildRequestParts: GET over TLS adds x-ssl-* headers, lower-cases, keeps duplicates as arrays", () => {
	const req = fakeRequest(
		"get",
		{ host: "suite:8443", "X-Mixed": "M", "set-cookie": ["a=1", "b=2"], accept: "*/*" },
		tlsSocket,
	);
	const parts = buildRequestParts(req, new URL("https://suite:8443/test/a/x/authorize?b=2&a=1&b=3"), null);
	assert.equal(
		JSON.stringify(parts),
		JSON.stringify({
			headers: {
				host: "suite:8443",
				"x-mixed": "M",
				"set-cookie": ["a=1", "b=2"],
				accept: "*/*",
				"x-ssl-protocol": "TLSv1.3",
				"x-ssl-cipher": "TLS_AES_128_GCM_SHA256",
			},
			query_string_params: { b: ["2", "3"], a: "1" },
			method: "GET",
			request_url: "https://suite:8443/test/a/x/authorize",
		}),
	);
});

test("buildRequestParts: x-ssl-* headers sent by a proxy win; none without TLS", () => {
	const proxied = fakeRequest("GET", { "x-ssl-protocol": "TLSv1.2", "x-ssl-cipher": "PROXY" }, tlsSocket);
	assert.deepEqual(buildRequestParts(proxied, new URL("https://s/x"), null)["headers"], {
		"x-ssl-protocol": "TLSv1.2",
		"x-ssl-cipher": "PROXY",
	});
	const plain = fakeRequest("GET", { host: "s" }, { encrypted: undefined });
	assert.deepEqual(buildRequestParts(plain, new URL("http://s/x"), null)["headers"], { host: "s" });
	const unencrypted = fakeRequest("GET", { host: "s" }, { ...tlsSocket, encrypted: false });
	assert.deepEqual(buildRequestParts(unencrypted, new URL("http://s/x"), null)["headers"], { host: "s" });
});

test("buildRequestParts: JSON bodies", () => {
	const ok = buildRequestParts(
		fakeRequest("POST", { "content-type": "Application/JSON; charset=utf-8" }),
		new URL("http://s/p?q=1"),
		'{"a":[1,{"b":null}]}',
	);
	assert.equal(
		JSON.stringify(ok),
		JSON.stringify({
			headers: { "content-type": "Application/JSON; charset=utf-8" },
			query_string_params: { q: "1" },
			method: "POST",
			request_url: "http://s/p",
			body: '{"a":[1,{"b":null}]}',
			body_json: { a: [1, { b: null }] },
		}),
	);
	const bad = buildRequestParts(
		fakeRequest("PUT", { "content-type": "application/json" }),
		new URL("http://s/p"),
		"{x",
	);
	assert.deepEqual(Object.keys(bad), [
		"headers",
		"query_string_params",
		"method",
		"request_url",
		"body",
		"body_json_parse_error",
	]);
	assert.equal(typeof bad["body_json_parse_error"], "string");
	assert.match(bad["body_json_parse_error"] as string, /JSON/);
});

test("buildRequestParts: form bodies and other content types", () => {
	const form = buildRequestParts(
		fakeRequest("POST", { "content-type": "application/x-www-form-urlencoded" }),
		new URL("http://s/token"),
		"grant_type=authorization_code&scope=a+b&scope=c",
	);
	assert.equal(
		JSON.stringify(form),
		JSON.stringify({
			headers: { "content-type": "application/x-www-form-urlencoded" },
			query_string_params: {},
			method: "POST",
			request_url: "http://s/token",
			body: "grant_type=authorization_code&scope=a+b&scope=c",
			body_form_params: { grant_type: "authorization_code", scope: ["a b", "c"] },
		}),
	);
	const text = buildRequestParts(fakeRequest("POST", { "content-type": "text/plain" }), new URL("http://s/x"), "#a=b");
	assert.deepEqual(Object.keys(text), ["headers", "query_string_params", "method", "request_url", "body"]);
	const noType = buildRequestParts(fakeRequest("POST", {}), new URL("http://s/x"), "{}");
	assert.equal(noType["body_json"], undefined);
});

// --- SuiteServer against a stand-in module ---

interface Call {
	kind: string;
	path: string;
	req: IncomingHttpRequest;
	res: unknown;
	session: HttpSession;
	requestParts: JsonObject;
}

class FakeModule {
	readonly log: TestInstanceEventLog;
	readonly calls: Call[] = [];
	readonly exceptions: [TestInterruptedException, string][] = [];
	released = 0;
	status = "WAITING";
	respond: (call: Call) => Response | Promise<Response> = () => new Response("ok");
	webfinger: ((...a: unknown[]) => Promise<JsonObject | Response | null>) | undefined;
	private readonly id: string;

	constructor(id: string) {
		this.id = id;
		this.log = new TestInstanceEventLog(id);
	}

	getId(): string {
		return this.id;
	}
	getName(): string {
		return "fake-module";
	}
	getEventLog(): TestInstanceEventLog {
		return this.log;
	}
	getStatus(): string {
		return this.status;
	}
	forceReleaseLock(): void {
		this.released++;
	}
	async handleException(error: TestInterruptedException, source: string): Promise<void> {
		this.exceptions.push([error, source]);
	}
	private record(kind: string, ...a: unknown[]): Promise<Response> {
		const [path, req, res, session, requestParts] = a as [
			string,
			IncomingHttpRequest,
			unknown,
			HttpSession,
			JsonObject,
		];
		const call = { kind, path, req, res, session, requestParts };
		this.calls.push(call);
		return Promise.resolve(this.respond(call));
	}
	handleHttp(...a: unknown[]): Promise<Response> {
		return this.record("http", ...a);
	}
	handleHttpMtls(...a: unknown[]): Promise<Response> {
		return this.record("mtls", ...a);
	}
	handleWellKnown(...a: unknown[]): Promise<Response> {
		return this.record("wellknown", ...a);
	}
	get handleWebfingerRequest(): ((...a: unknown[]) => Promise<JsonObject | Response | null>) | undefined {
		return this.webfinger;
	}
}

let server: SuiteServer;
let base: string;
const mod = new FakeModule("tid1");
const other = new FakeModule("tid2");

before(async () => {
	server = new SuiteServer();
	base = await server.start();
	const reg = server.register(mod as unknown as AbstractTestModule, { alias: "my alias", wellKnown: true });
	assert.deepEqual(reg, { url: base + "/test/a/my%20alias", mtlsUrl: base + "/test-mtls/a/my%20alias" });
	assert.deepEqual(server.register(other as unknown as AbstractTestModule), {
		url: base + "/test/tid2",
		mtlsUrl: base + "/test-mtls/tid2",
	});
});

after(() => server.stop());

function last(m: FakeModule, n: number): LogEntry[] {
	return m.log.entries.slice(-n);
}

const INCOMING_KEYS = [
	"_id",
	"testId",
	"src",
	"time",
	"seq",
	"msg",
	"http",
	"incoming_path",
	"incoming_query_string_params",
	"incoming_body_form_params",
	"incoming_method",
	"incoming_headers",
	"incoming_body",
	"incoming_body_json",
	"incoming_body_json_parse_error",
];
const OUTGOING_KEYS = [
	"_id",
	"testId",
	"src",
	"time",
	"seq",
	"msg",
	"http",
	"outgoing_path",
	"outgoing_status_code",
	"outgoing_headers",
];

test("server: routes /test/a/{alias}/..., logs the exchange, sets the session cookie and merges set-cookie", async () => {
	mod.respond = () =>
		new Response("hello", {
			status: 201,
			headers: [
				["content-type", "text/plain"],
				["set-cookie", "m1=1"],
				["set-cookie", "m2=2"],
				["x-custom", "c"],
			],
		});
	const res = await fetch(base + "/test/a/my%20alias/some/path?b=2&a=1", {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: "x=1&x=2",
	});
	assert.equal(res.status, 201);
	assert.equal(await res.text(), "hello");
	assert.equal(res.headers.get("x-custom"), "c");
	const cookies = res.headers.getSetCookie();
	assert.equal(cookies.length, 3);
	assert.match(cookies[0], /^CONFORMANCE_SESSION=[0-9a-f-]{36}; Path=\/; HttpOnly; SameSite=Lax$/);
	assert.deepEqual(cookies.slice(1), ["m1=1", "m2=2"]);

	const call = mod.calls.at(-1) as Call;
	assert.equal(call.kind, "http");
	assert.equal(call.path, "some/path");
	assert.equal(call.res, null);
	assert.ok(call.session instanceof Map);
	assert.equal(call.req.method, "POST");
	assert.equal(call.req.url, base + "/test/a/my%20alias/some/path?b=2&a=1");
	assert.equal(call.req.tls, undefined);
	assert.equal(call.req.headers["content-type"], "application/x-www-form-urlencoded");
	assert.ok(call.req.remoteAddress);
	assert.deepEqual(Object.keys(call.requestParts), [
		"headers",
		"query_string_params",
		"method",
		"request_url",
		"body",
		"body_form_params",
	]);
	assert.equal(call.requestParts["request_url"], base + "/test/a/my%20alias/some/path");

	const [incoming, outgoing] = last(mod, 2);
	assert.deepEqual(Object.keys(incoming), INCOMING_KEYS);
	assert.equal(incoming.src, "fake-module");
	assert.equal(incoming["msg"], "Incoming HTTP request to test instance tid1");
	assert.equal(incoming["http"], "incoming");
	assert.equal(incoming["incoming_path"], "/test/a/my%20alias/some/path");
	assert.deepEqual(incoming["incoming_query_string_params"], { b: "2", a: "1" });
	assert.deepEqual(incoming["incoming_body_form_params"], { x: ["1", "2"] });
	assert.equal(incoming["incoming_method"], "POST");
	assert.deepEqual(incoming["incoming_headers"], call.requestParts["headers"]);
	assert.equal(incoming["incoming_body"], "x=1&x=2");
	assert.equal(incoming["incoming_body_json"], undefined);

	assert.deepEqual(Object.keys(outgoing), OUTGOING_KEYS);
	assert.equal(outgoing.src, "fake-module");
	assert.equal(outgoing["msg"], "Response to HTTP request to test instance tid1");
	assert.equal(outgoing["http"], "outgoing");
	assert.equal(outgoing["outgoing_path"], "/test/a/my%20alias/some/path");
	assert.equal(outgoing["outgoing_status_code"], 201);
	assert.deepEqual(outgoing["outgoing_headers"], {
		"content-type": "text/plain",
		// Headers.forEach() yields each set-cookie separately, the last one is kept
		"set-cookie": "m2=2",
		"x-custom": "c",
	});

	// the session is kept for a returning browser
	mod.respond = () => new Response("ok");
	const again = await fetch(base + "/test/tid1/next", { headers: { cookie: cookies[0].split(";")[0] } });
	assert.equal(again.status, 200);
	assert.deepEqual(again.headers.getSetCookie(), []);
	assert.equal(mod.calls.at(-1)?.session, call.session);
	assert.equal(mod.calls.at(-1)?.path, "next");
	assert.deepEqual(Object.keys(mod.calls.at(-1)?.requestParts ?? {}), [
		"headers",
		"query_string_params",
		"method",
		"request_url",
	]);
});

test("server: binary and empty bodies are sent unchanged", async () => {
	const bytes = new Uint8Array(70_000).map((_, i) => i % 256);
	mod.respond = () => new Response(bytes, { headers: { "content-type": "application/octet-stream" } });
	const res = await fetch(base + "/test/tid1/bin");
	assert.deepEqual(new Uint8Array(await res.arrayBuffer()), bytes);
	mod.respond = () => new Response(null, { status: 204 });
	const empty = await fetch(base + "/test/tid1/empty");
	assert.equal(empty.status, 204);
	assert.equal(await empty.text(), "");
	mod.respond = () => new Response(null, { status: 302, headers: { location: "https://rp/cb?x=1" } });
	const redirect = await fetch(base + "/test/tid1/r", { redirect: "manual" });
	assert.equal(redirect.status, 302);
	assert.equal(redirect.headers.get("location"), "https://rp/cb?x=1");
});

test("server: /test-mtls/ and /.well-known/ routes", async () => {
	mod.respond = () => new Response("m");
	await fetch(base + "/test-mtls/a/my%20alias/token", {
		method: "POST",
		body: '{"a":1}',
		headers: { "content-type": "application/json" },
	});
	let call = mod.calls.at(-1) as Call;
	assert.equal(call.kind, "mtls");
	assert.equal(call.path, "token");
	assert.deepEqual(call.requestParts["body_json"], { a: 1 });
	assert.equal(last(mod, 2)[0]["incoming_path"], "/test-mtls/a/my%20alias/token");

	await fetch(base + "/.well-known/openid-configuration");
	call = mod.calls.at(-1) as Call;
	assert.equal(call.kind, "wellknown");
	assert.equal(call.path, "/.well-known/openid-configuration");
	assert.equal(last(mod, 1)[0]["outgoing_path"], "/.well-known/openid-configuration");

	await fetch(base + "/test/tid2/x");
	assert.equal(other.calls.at(-1)?.path, "x");
});

test("server: errors thrown by the module are handed to it and answered with 400", async () => {
	const released = mod.released;
	mod.respond = () => {
		throw TestFailureException.oauthError("tid1", "invalid_request", "bad things");
	};
	let res = await fetch(base + "/test/tid1/fail");
	assert.equal(res.status, 400);
	assert.equal(res.headers.get("content-type"), "application/json");
	assert.equal(await res.text(), '{"error":"invalid_request","error_description":"bad things"}');
	assert.equal(mod.released, released + 1);
	const [error, source] = mod.exceptions.at(-1) ?? [];
	assert.equal(source, "incoming HTTP request");
	assert.equal(error?.message, "invalid_request");
	const outgoing = last(mod, 1)[0];
	assert.equal(outgoing["outgoing_status_code"], 400);
	assert.deepEqual(outgoing["outgoing_headers"], { "content-type": "application/json" });

	mod.respond = () => {
		throw new Error("plain error");
	};
	res = await fetch(base + "/test/tid1/fail2");
	assert.equal(await res.text(), '{"error":"plain error"}');
	const [wrapped] = mod.exceptions.at(-1) ?? [];
	assert.ok(wrapped instanceof TestFailureException);
	assert.equal(wrapped.getTestId(), "tid1");
	assert.equal(wrapped.cause instanceof Error && wrapped.cause.message, "plain error");

	mod.respond = () => new Response("ok");
	const failing = mod.handleException;
	mod.handleException = () => Promise.reject(new Error("handler broke"));
	res = await fetch(base + "/test/tid1/x");
	assert.equal(res.status, 200, "handleException is not called on success");
	mod.respond = () => {
		throw new Error("again");
	};
	res = await fetch(base + "/test/tid1/x");
	assert.equal(res.status, 500);
	assert.equal(await res.text(), '{"error":"handler broke"}');
	mod.handleException = failing;
});

const WF = "/.well-known/webfinger";

async function expectResponse(path: string, status: number, body: string): Promise<void> {
	const res = await fetch(base + path);
	assert.equal(res.status, status, path);
	assert.equal(await res.text(), body, path);
}

test("server: not found responses", async () => {
	await expectResponse("/nothing", 404, '{"error":"not found"}');
	await expectResponse("/test/a/nope/x", 404, `{"error":"No test found with alias 'nope'"}`);
	await expectResponse("/test/nope/x", 404, `{"error":"No running test with test id 'nope'"}`);
	server.unregister(mod as unknown as AbstractTestModule);
	try {
		await expectResponse(
			"/.well-known/openid-configuration",
			404,
			'{"error":"No running test serves /.well-known/openid-configuration"}',
		);
		await expectResponse("/test/a/my%20alias/x", 404, `{"error":"No test found with alias 'my alias'"}`);
		await expectResponse("/test/tid1/x", 404, `{"error":"No running test with test id 'tid1'"}`);
	} finally {
		server.register(mod as unknown as AbstractTestModule, { alias: "my alias", wellKnown: true });
	}
});

test("server: webfinger", async () => {
	server.register(other as unknown as AbstractTestModule, { alias: "wf" });
	await expectResponse(WF + "", 400, '{"error":"resource parameter missing"}');
	await expectResponse(WF + "?resource=nonsense", 400, "");
	await expectResponse(
		WF + "?resource=acct:nobody.testname@host",
		404,
		`{"error":"no running test for test id 'nobody' from alias 'nobody'"}`,
	);
	other.webfinger = undefined;
	await expectResponse(WF + "?resource=acct:wf.testname@host", 400, "");

	const seen: unknown[][] = [];
	other.webfinger = async (...a) => {
		seen.push(a);
		return { subject: "s" };
	};
	const logged = other.log.entries.length;
	await expectResponse(WF + "?resource=acct:wf.oidcc-client-test@host:1&rel=x", 200, '{"subject":"s"}');
	assert.deepEqual(seen[0].slice(0, 3), ["oidcc-client-test", "acct", "acct:wf.oidcc-client-test@host:1"]);
	const parts = seen[0][3] as JsonObject;
	assert.deepEqual(Object.keys(parts), ["headers", "query_string_params", "method"]);
	assert.deepEqual(parts["query_string_params"], { resource: "acct:wf.oidcc-client-test@host:1", rel: "x" });
	assert.equal(parts["method"], "GET");
	const [incoming, outgoing] = other.log.entries.slice(logged);
	assert.equal(other.log.entries.length, logged + 2);
	assert.deepEqual(Object.keys(incoming), INCOMING_KEYS);
	assert.equal(incoming["msg"], "Incoming HTTP request to test instance tid2");
	assert.equal(incoming["incoming_path"], "/.well-known/webfinger");
	assert.equal(incoming["incoming_body_form_params"], undefined);
	assert.deepEqual(Object.keys(outgoing), OUTGOING_KEYS);
	assert.equal(outgoing["outgoing_path"], "/.well-known/webfinger");
	assert.deepEqual(outgoing["outgoing_headers"], { "content-type": "application/json" });

	seen.length = 0;
	await expectResponse(WF + "?resource=ACCT:wf.T1@host", 200, '{"subject":"s"}');
	await expectResponse(WF + "?resource=HTTP://host/a/b/wf/T2", 200, '{"subject":"s"}');
	assert.deepEqual(
		seen.map((a) => a.slice(0, 2)),
		[
			["T1", "acct"],
			["T2", "https"],
		],
	);

	other.webfinger = async () => null;
	await expectResponse(WF + "?resource=https://host/wf/testname", 200, "{}");
	other.webfinger = async () => new Response("custom", { status: 202 });
	await expectResponse(WF + "?resource=http://host/x/wf/testname", 202, "custom");

	other.status = "CREATED";
	const released = other.released;
	await expectResponse(
		WF + "?resource=acct:wf.x@h",
		400,
		'{"error":"Please wait for the test to be in WAITING state. The current status is CREATED"}',
	);
	assert.equal(other.released, released + 1);
	assert.equal(other.exceptions.at(-1)?.[1], "incoming webfinger request");
	assert.equal(other.log.entries.at(-1)?.["http"], "incoming", "no outgoing entry for a failed webfinger request");
	other.status = "WAITING";

	other.webfinger = async () => {
		throw new Error("wf broke");
	};
	await expectResponse(WF + "?resource=acct:wf.x@h", 400, '{"error":"wf broke"}');
	other.webfinger = undefined;
});
