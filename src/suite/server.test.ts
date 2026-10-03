import { afterEach, beforeEach, expect, test } from "vitest";
import { createLog, type EventLog } from "./log.ts";
import { startServer, type TestServer } from "./server.ts";

let log: EventLog;
let server: TestServer;

beforeEach(async () => {
	log = createLog("abc123");
	server = await startServer({ log, testName: "oidcc-server", alias: "my-op" });
});
afterEach(() => server.close());

test("the base url is /test/a/<alias> on a free port", () => {
	expect(server.baseUrl).toMatch(/^http:\/\/localhost:\d+\/test\/a\/my-op$/);
});

test("waitFor resolves with upstream's requestParts after the handler answered", async () => {
	const callback = server.waitFor("callback", (req) => Response.json({ seen: req.query_string_params }));
	const res = await fetch(server.baseUrl + "/callback?code=c&x=1&x=2", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Custom": "A" },
		body: "state=s&state=t",
	});
	expect(await res.json()).toEqual({ seen: { code: "c", x: ["1", "2"] } });
	const req = await callback;
	expect(req).toMatchObject({
		method: "POST",
		path: "callback",
		request_url: server.baseUrl + "/callback",
		query_string_params: { code: "c", x: ["1", "2"] },
		body: "state=s&state=t",
		body_form_params: { state: ["s", "t"] },
	});
	expect(req.headers["x-custom"]).toBe("A");
	expect(log.entries.map((e) => [e.src, e["msg"], e["http"]])).toEqual([
		["oidcc-server", "Incoming HTTP request to test instance abc123", "incoming"],
		["oidcc-server", "Response to HTTP request to test instance abc123", "outgoing"],
	]);
	expect(log.entries[0]).toMatchObject({ incoming_path: "/test/a/my-op/callback", incoming_method: "POST" });
	expect(log.entries[1]).toMatchObject({ outgoing_status_code: 200 });
});

test("JSON bodies are parsed; persistent handlers answer every request; unknown paths are 404", async () => {
	let calls = 0;
	server.on("token", (req) => Response.json({ n: ++calls, json: req.body_json }));
	for (const n of [1, 2]) {
		const res = await fetch(server.baseUrl + "/token", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: '{"a":1}',
		});
		expect(await res.json()).toEqual({ n, json: { a: 1 } });
	}
	expect((await fetch(server.baseUrl + "/nothing")).status).toBe(404);
	expect((await fetch(server.origin + "/elsewhere")).status).toBe(404);
});

test("waitFor rejects after its timeout", async () => {
	await expect(server.waitFor("never", undefined, { timeoutSeconds: 0.05 })).rejects.toThrow(
		"Timed out after 0.05 seconds waiting for a request to /test/a/my-op/never",
	);
});
