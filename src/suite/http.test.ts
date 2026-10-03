import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";
import { endpointResponse, HttpError, jsonBody, request } from "./http.ts";
import { createLog, useLog, type EventLog } from "./log.ts";

const server = setupServer();
let log: EventLog;
let uninstall: () => void;

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterAll(() => server.close());
beforeEach(() => {
	log = createLog("t1");
	uninstall = useLog(log);
});
afterEach(() => {
	server.resetHandlers();
	uninstall();
});

describe("request", () => {
	test("logs the request and the response under the calling condition, as upstream's LoggingRequestInterceptor", async () => {
		let seen: Request | undefined;
		server.use(
			http.post("https://op.example/token", async ({ request: req }) => {
				seen = req.clone();
				return HttpResponse.json({ access_token: "at" }, { headers: { "Set-Cookie": "a=1" } });
			}),
		);
		const res = await request("CallTokenEndpoint", {
			url: "https://op.example/token",
			method: "POST",
			headers: { Authorization: "Basic eA==" },
			body: new URLSearchParams({ grant_type: "authorization_code", code: "c" }),
		});

		expect(await seen?.text()).toBe("grant_type=authorization_code&code=c");
		expect(seen?.headers.get("content-type")).toBe("application/x-www-form-urlencoded;charset=UTF-8");
		expect(res.status).toBe(200);
		expect(jsonBody(res)).toEqual({ ok: true, value: { access_token: "at" } });

		const [req, resp] = log.entries;
		expect(req).toMatchObject({
			src: "CallTokenEndpoint",
			msg: "HTTP request",
			http: "request",
			request_uri: "https://op.example/token",
			request_method: "POST",
			request_body: "grant_type=authorization_code&code=c",
			request_headers: {
				authorization: "Basic eA==",
				"accept-encoding": "identity",
				"content-type": "application/x-www-form-urlencoded;charset=UTF-8",
				"user-agent": "openid-conformance-suite",
			},
		});
		expect(resp).toMatchObject({
			src: "CallTokenEndpoint",
			msg: "HTTP response",
			http: "response",
			// a string, as upstream logs HttpStatusCode.toString()
			response_status_code: "200",
			response_status_text: "OK",
			response_body: '{"access_token":"at"}',
		});
		expect((resp["response_headers"] as Record<string, unknown>)["content-type"]).toBe("application/json");
	});

	test("does not follow redirects and treats no status as an error", async () => {
		server.use(
			http.get("https://op.example/a", () => new HttpResponse(null, { status: 302, headers: { Location: "/b" } })),
			http.get("https://op.example/err", () => HttpResponse.text("nope", { status: 500 })),
		);
		const redirect = await request("X", { url: "https://op.example/a" });
		expect(redirect.status).toBe(302);
		expect(redirect.headers.get("location")).toBe("/b");
		expect(redirect.body).toBeNull();
		const error = await request("X", { url: "https://op.example/err" });
		expect([error.status, error.body]).toEqual([500, "nope"]);
		expect(log.entries.filter((e) => e["http"] === "response").map((e) => e["response_body"])).toEqual(["", "nope"]);
	});

	test("binary bodies are not logged as text", async () => {
		server.use(http.get("https://op.example/bin", () => new HttpResponse(new Uint8Array([0xff, 0x00, 0x41]))));
		await request("X", { url: "https://op.example/bin" });
		expect(log.entries[1]).toMatchObject({
			response_body_omitted: "binary content, 3 bytes - not shown (not valid UTF-8)",
			response_body_first_bytes: "\\xff\\x00A",
		});
	});

	test("network errors throw HttpError after logging the request", async () => {
		server.use(http.get("https://op.example/down", () => HttpResponse.error()));
		await expect(request("X", { url: "https://op.example/down" })).rejects.toThrow(HttpError);
		await expect(request("X", { url: "https://op.example/down" })).rejects.toThrow(
			/^I\/O error on GET request for "https:\/\/op.example\/down"/,
		);
		expect(log.entries.map((e) => e["msg"])).toEqual(["HTTP request", "HTTP request"]);
	});

	test("endpointResponse is upstream's environment shape", async () => {
		server.use(http.get("https://op.example/j", () => HttpResponse.json({ a: 1 }, { status: 201 })));
		const res = await request("X", { url: "https://op.example/j" });
		expect(endpointResponse("discovery", res)).toEqual({
			status: 201,
			endpoint_name: "discovery",
			headers: expect.objectContaining({ "content-type": "application/json" }),
			body: '{"a":1}',
			body_json: { a: 1 },
		});
	});
});
