import assert from "node:assert/strict";
import { createServer, request, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import type { JsonObject } from "./json.ts";
import { buildRequestParts, convertQueryStringParamsToMap } from "./server.ts";

/*
 * Pins the `requestParts` object handed to test modules for incoming requests (Java: TestDispatcher.handle).
 */

/** Sends one raw request to a real node:http server and returns buildRequestParts() for it */
async function partsFor(
	method: string,
	path: string,
	headers: [string, string][],
	body: string | null,
): Promise<{ parts: JsonObject; base: string }> {
	let parts: JsonObject | null = null;
	const server = createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (c: Buffer) => chunks.push(c));
		req.on("end", () => {
			const url = new URL(req.url ?? "/", base);
			// server.ts readBody(): null for GET/HEAD and for an empty body
			const text = req.method === "GET" || chunks.length === 0 ? null : Buffer.concat(chunks).toString("utf8");
			parts = buildRequestParts(req, url, text);
			res.end();
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const port = (server.address() as AddressInfo).port;
	const base = `http://localhost:${port}`;
	await new Promise<void>((resolve, reject) => {
		// raw headers (to send duplicates) need an explicit Host header
		const flat = [["Host", `127.0.0.1:${port}`], ...headers].flat();
		const req = request({ host: "127.0.0.1", port, method, path, headers: flat }, (res) => {
			res.resume();
			res.on("end", resolve);
		});
		req.on("error", reject);
		req.end(body ?? undefined);
	});
	await new Promise<void>((resolve) => server.close(() => resolve()));
	assert.ok(parts);
	return { parts, base };
}

test("GET with query string; header lower-casing and duplicates", async () => {
	const { parts, base } = await partsFor(
		"GET",
		"/test/abc/callback?state=s1&a=1&a=2&empty=&sp=a%20b+c",
		[
			["X-Mixed-Case", "v"],
			["X-Dup", "one"],
			["X-Dup", "two"],
			["Cookie", "c1=1"],
			["Cookie", "c2=2"],
			["Set-Cookie", "s=1"],
			["Set-Cookie", "s=2"],
		],
		null,
	);
	const port = base.split(":")[2];
	const expectedHeaders = {
		host: `127.0.0.1:${port}`,
		"x-mixed-case": "v",
		"x-dup": "one, two", // node joins duplicates ...
		cookie: "c1=1; c2=2", // ... cookies with "; "
		"set-cookie": ["s=1", "s=2"], // ... except set-cookie, which stays an array
		connection: "keep-alive",
	};
	assert.deepEqual(Object.keys(parts["headers"] as JsonObject), Object.keys(expectedHeaders));
	assert.deepEqual(parts, {
		headers: expectedHeaders,
		query_string_params: { state: "s1", a: ["1", "2"], empty: "", sp: "a b c" },
		method: "GET",
		request_url: base + "/test/abc/callback",
	});
	assert.deepEqual(Object.keys(parts), ["headers", "query_string_params", "method", "request_url"]);
});

test("form POST", async () => {
	const { parts } = await partsFor(
		"POST",
		"/token",
		[["Content-Type", "application/x-www-form-urlencoded;charset=UTF-8"]],
		"grant_type=authorization_code&code=a%2Bb&scope=openid+email&x=1&x=2",
	);
	assert.deepEqual(Object.keys(parts), [
		"headers",
		"query_string_params",
		"method",
		"request_url",
		"body",
		"body_form_params",
	]);
	assert.deepEqual(parts["query_string_params"], {});
	assert.equal(parts["method"], "POST");
	assert.equal(parts["body"], "grant_type=authorization_code&code=a%2Bb&scope=openid+email&x=1&x=2");
	assert.deepEqual(parts["body_form_params"], {
		grant_type: "authorization_code",
		code: "a+b",
		scope: "openid email",
		x: ["1", "2"],
	});
});

test("JSON POST, invalid JSON, other content types", async () => {
	const json = await partsFor("POST", "/reg", [["Content-Type", "application/json; charset=utf-8"]], '{"a":[1]}');
	assert.deepEqual(Object.keys(json.parts), [
		"headers",
		"query_string_params",
		"method",
		"request_url",
		"body",
		"body_json",
	]);
	assert.deepEqual(json.parts["body_json"], { a: [1] });

	const invalid = await partsFor("PUT", "/reg", [["Content-Type", "application/json"]], "not json");
	assert.equal(invalid.parts["method"], "PUT");
	assert.equal(invalid.parts["body"], "not json");
	assert.equal(invalid.parts["body_json"], undefined);
	assert.equal(invalid.parts["body_json_parse_error"], `Unexpected token 'o', "not json" is not valid JSON`);

	const text = await partsFor("POST", "/x", [["Content-Type", "text/plain"]], "a=b");
	assert.deepEqual(Object.keys(text.parts), ["headers", "query_string_params", "method", "request_url", "body"]);

	const empty = await partsFor("POST", "/x", [["Content-Type", "application/json"]], null);
	assert.equal("body" in empty.parts, false);
});

function fakeRequest(socket: object, headers: IncomingMessage["headers"] = {}): IncomingMessage {
	return { method: "get", headers, socket } as unknown as IncomingMessage;
}

test("x-ssl-protocol / x-ssl-cipher are added for TLS sockets only", () => {
	const url = new URL("https://localhost:8443/test/id/path?q=1#frag");
	const tls = { encrypted: true, getProtocol: () => "TLSv1.3", getCipher: () => ({ name: "TLS_AES_128_GCM_SHA256" }) };
	assert.deepEqual(buildRequestParts(fakeRequest(tls, { host: "h" }), url, null), {
		headers: { host: "h", "x-ssl-protocol": "TLSv1.3", "x-ssl-cipher": "TLS_AES_128_GCM_SHA256" },
		query_string_params: { q: "1" },
		method: "GET",
		request_url: "https://localhost:8443/test/id/path",
	});
	// headers already set by a proxy win
	const proxied = buildRequestParts(fakeRequest(tls, { "x-ssl-cipher": "FROM-PROXY" }), url, null);
	assert.deepEqual(proxied["headers"], { "x-ssl-cipher": "FROM-PROXY", "x-ssl-protocol": "TLSv1.3" });
	// not encrypted, or no getCipher: nothing added
	assert.deepEqual(buildRequestParts(fakeRequest({ ...tls, encrypted: false }), url, null)["headers"], {});
	assert.deepEqual(buildRequestParts(fakeRequest({ encrypted: true }), url, null)["headers"], {});
	// a null protocol is not added
	const noProto = { encrypted: true, getProtocol: () => null, getCipher: () => ({ name: "C" }) };
	assert.deepEqual(buildRequestParts(fakeRequest(noProto), url, null)["headers"], { "x-ssl-cipher": "C" });
});

test("convertQueryStringParamsToMap", () => {
	assert.deepEqual(convertQueryStringParamsToMap(null), []);
	assert.deepEqual(convertQueryStringParamsToMap(""), []);
	assert.deepEqual(convertQueryStringParamsToMap("a=1&b&a=%20+"), [
		["a", "1"],
		["b", ""],
		["a", "  "],
	]);
});
