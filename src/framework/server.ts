import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { TLSSocket } from "node:tls";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import type { AbstractTestModule } from "./AbstractTestModule.ts";
import { args, mapToJsonObject } from "./DataUtils.ts";
import { TestFailureException, TestInterruptedException } from "./exceptions.ts";
import { parseJson, type JsonObject } from "./json.ts";
import type { HttpSession, IncomingHttpRequest } from "./TestModule.ts";
import { jsonResponse } from "./views.ts";

export const TEST_PATH = "/test/"; // path for incoming test requests
export const TEST_MTLS_PATH = "/test-mtls/"; // path for incoming MTLS requests

export interface SuiteServerOptions {
	host?: string;
	port?: number;
	/** Serve HTTPS with this certificate (PEM) */
	tls?: { cert: string; key: string; ca?: string; requestCert?: boolean };
	/** The URL other parties should use to reach this server (defaults to http://host:port) */
	externalUrl?: string;
}

/**
 * Port of runner/TestDispatcher.java: the HTTP front door for running tests.
 *
 *   /test/{testId}/{path}   -> module.handleHttp(path, ...)
 *   /test/a/{alias}/{path}  -> module registered under alias
 *   /test-mtls/...          -> module.handleHttpMtls(...)
 *   /.well-known/{rest}     -> module.handleWellKnown(...) of the module registered with `wellKnown: true`
 */
export class SuiteServer {
	private readonly server: Server;
	private readonly tests = new Map<string, AbstractTestModule>();
	private readonly aliases = new Map<string, string>();
	private wellKnownTestId: string | null = null;
	private readonly sessions = new Map<string, HttpSession>();
	private readonly opts: SuiteServerOptions;
	private baseUrl = "";

	constructor(opts: SuiteServerOptions = {}) {
		this.opts = opts;
		const handler = (req: IncomingMessage, res: ServerResponse) => {
			this.handle(req, res).catch((e) => {
				if (!res.headersSent) {
					res.writeHead(500, { "content-type": "application/json" });
				}
				res.end(JSON.stringify({ error: String((e as Error).message ?? e) }));
			});
		};
		this.server = opts.tls
			? createHttpsServer(
					{
						cert: opts.tls.cert,
						key: opts.tls.key,
						ca: opts.tls.ca,
						requestCert: opts.tls.requestCert ?? false,
						rejectUnauthorized: false,
					},
					handler,
				)
			: createServer(handler);
	}

	async start(): Promise<string> {
		await new Promise<void>((resolve, reject) => {
			this.server.once("error", reject);
			this.server.listen(this.opts.port ?? 0, this.opts.host ?? "127.0.0.1", () => resolve());
		});
		const addr = this.server.address() as AddressInfo;
		const host = this.opts.host ?? "localhost";
		const scheme = this.opts.tls ? "https" : "http";
		this.baseUrl =
			this.opts.externalUrl?.replace(/\/$/, "") ??
			`${scheme}://${host === "0.0.0.0" || host === "127.0.0.1" ? "localhost" : host}:${addr.port}`;
		return this.baseUrl;
	}

	getBaseUrl(): string {
		return this.baseUrl;
	}

	getPort(): number {
		return (this.server.address() as AddressInfo).port;
	}

	async stop(): Promise<void> {
		this.server.closeAllConnections?.();
		await new Promise<void>((resolve) => this.server.close(() => resolve()));
	}

	/** Register a running test; returns the base URL other parties use for it (Java: TestRunner.createTest) */
	register(
		test: AbstractTestModule,
		opts: { alias?: string | null; wellKnown?: boolean } = {},
	): { url: string; mtlsUrl: string } {
		this.tests.set(test.getId(), test);
		let path = test.getId();
		if (opts.alias) {
			this.aliases.set(opts.alias, test.getId());
			path = "a/" + encodeURIComponent(opts.alias);
		}
		if (opts.wellKnown) {
			this.wellKnownTestId = test.getId();
		}
		return { url: this.baseUrl + TEST_PATH + path, mtlsUrl: this.baseUrl + TEST_MTLS_PATH + path };
	}

	unregister(test: AbstractTestModule): void {
		this.tests.delete(test.getId());
		for (const [alias, id] of this.aliases) {
			if (id === test.getId()) {
				this.aliases.delete(alias);
			}
		}
		if (this.wellKnownTestId === test.getId()) {
			this.wellKnownTestId = null;
		}
	}

	private session(req: IncomingMessage, res: ServerResponse): HttpSession {
		const cookie = req.headers["cookie"] ?? "";
		const m = /(?:^|;\s*)CONFORMANCE_SESSION=([^;]+)/.exec(cookie);
		let id = m?.[1];
		if (!id || !this.sessions.has(id)) {
			id = randomUUID();
			this.sessions.set(id, new Map());
			res.setHeader("set-cookie", `CONFORMANCE_SESSION=${id}; Path=/; HttpOnly; SameSite=Lax`);
		}
		return this.sessions.get(id) as HttpSession;
	}

	private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
		const url = new URL(req.url ?? "/", this.baseUrl);
		const pathname = url.pathname;
		let kind: "test" | "mtls" | "wellknown";
		let rest: string;
		if (pathname === "/.well-known/webfinger") {
			await this.send(res, await this.handleWebfinger(req, url));
			return;
		}
		if (pathname.startsWith(TEST_PATH)) {
			kind = "test";
			rest = pathname.substring(TEST_PATH.length);
		} else if (pathname.startsWith(TEST_MTLS_PATH)) {
			kind = "mtls";
			rest = pathname.substring(TEST_MTLS_PATH.length);
		} else if (pathname.startsWith("/.well-known/")) {
			kind = "wellknown";
			rest = pathname;
		} else {
			await this.send(res, jsonResponse({ error: "not found" }, 404));
			return;
		}

		let test: AbstractTestModule | undefined;
		let restOfPath: string;
		if (kind === "wellknown") {
			test = this.wellKnownTestId ? this.tests.get(this.wellKnownTestId) : undefined;
			restOfPath = rest;
			if (!test) {
				await this.send(res, jsonResponse({ error: "No running test serves " + pathname }, 404));
				return;
			}
		} else {
			const pathParts = rest.split("/");
			let testId = pathParts.shift() ?? "";
			if (testId === "a") {
				const alias = decodeURIComponent(pathParts.shift() ?? "");
				const id = this.aliases.get(alias);
				if (!id) {
					await this.send(res, jsonResponse({ error: "No test found with alias '" + alias + "'" }, 404));
					return;
				}
				testId = id;
			}
			test = this.tests.get(testId);
			if (!test) {
				await this.send(res, jsonResponse({ error: "No running test with test id '" + testId + "'" }, 404));
				return;
			}
			restOfPath = pathParts.join("/");
		}

		const body = await readBody(req);
		const requestParts = buildRequestParts(req, url, body);
		const incoming = toIncomingRequest(req, url);
		const session = this.session(req, res);
		logIncomingHttpRequest(test, pathname, requestParts);

		let response: Response;
		try {
			if (kind === "test") {
				response = await test.handleHttp(restOfPath, incoming, null, session, requestParts);
			} else if (kind === "mtls") {
				response = await test.handleHttpMtls(restOfPath, incoming, null, session, requestParts);
			} else {
				response = await test.handleWellKnown(restOfPath, incoming, null, session, requestParts);
			}
		} catch (e) {
			test.forceReleaseLock();
			let error: TestInterruptedException;
			if (e instanceof TestInterruptedException) {
				error = e;
			} else {
				error = new TestFailureException(test.getId(), e);
			}
			// Java: TestDispatcher catches the exception, hands it to the test and returns an error response
			await test.handleException(error, "incoming HTTP request");
			const tfe = error instanceof TestFailureException ? error : null;
			const errBody: JsonObject = { error: tfe?.getError() ?? error.message };
			if (tfe?.getErrorDescription()) {
				errBody["error_description"] = tfe.getErrorDescription();
			}
			response = jsonResponse(errBody, 400);
		}
		logOutgoingHttpResponse(test, pathname, response);
		await this.send(res, response);
	}

	/** Port of TestDispatcher.handleWellKnownWebFingerRequest: routes webfinger to the RP test module named in `resource` */
	private async handleWebfinger(req: IncomingMessage, url: URL): Promise<Response> {
		const resource = url.searchParams.get("resource");
		if (resource == null) {
			// https://tools.ietf.org/html/rfc7033#section-4
			return jsonResponse({ error: "resource parameter missing" }, 400);
		}
		let testName: string;
		let alias: string;
		let resourcePrefix: string;
		const acct = /^acct:([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)@.*$/i.exec(resource);
		const https = /^https?:\/\/.*\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)$/i.exec(resource);
		if (acct) {
			resourcePrefix = "acct";
			alias = acct[1];
			testName = acct[2];
		} else if (https) {
			resourcePrefix = "https";
			alias = https[1];
			testName = https[2];
		} else {
			return new Response(null, { status: 400 });
		}
		const testId = this.aliases.get(alias) ?? alias;
		const test = this.tests.get(testId);
		if (!test) {
			return jsonResponse({ error: "no running test for test id '" + testId + "' from alias '" + alias + "'" }, 404);
		}
		const clientTest = test as AbstractTestModule & {
			handleWebfingerRequest?: (
				testName: string,
				prefix: string,
				resource: string,
				parts: JsonObject,
			) => Promise<JsonObject | Response | null>;
		};
		if (typeof clientTest.handleWebfingerRequest !== "function") {
			return new Response(null, { status: 400 });
		}
		const requestParts: JsonObject = {
			headers: mapToJsonObject(req.headers as Record<string, string | string[] | undefined>, true),
			query_string_params: mapToJsonObject(convertQueryStringParamsToMap(url.search.substring(1)), false),
			method: (req.method ?? "GET").toUpperCase(),
		};
		logIncomingHttpRequest(test, "/.well-known/webfinger", requestParts);
		try {
			if (test.getStatus() === "CREATED") {
				throw new TestFailureException(
					test.getId(),
					"Please wait for the test to be in WAITING state. The current status is CREATED",
				);
			}
			const response = await clientTest.handleWebfingerRequest(testName, resourcePrefix, resource, requestParts);
			const out = response instanceof Response ? response : jsonResponse(response ?? {}, 200);
			logOutgoingHttpResponse(test, "/.well-known/webfinger", out);
			return out;
		} catch (e) {
			test.forceReleaseLock();
			const error = e instanceof TestInterruptedException ? e : new TestFailureException(test.getId(), e);
			await test.handleException(error, "incoming webfinger request");
			return jsonResponse({ error: error.message }, 400);
		}
	}

	private async send(res: ServerResponse, response: Response): Promise<void> {
		const headers: Record<string, string | string[]> = {};
		response.headers.forEach((v, k) => {
			headers[k] = v;
		});
		const setCookie = response.headers.getSetCookie();
		if (setCookie.length > 0) {
			headers["set-cookie"] = setCookie;
		}
		const existing = res.getHeader("set-cookie");
		if (existing) {
			headers["set-cookie"] = ([] as string[]).concat(
				existing as string | string[],
				(headers["set-cookie"] as string[] | undefined) ?? [],
			);
		}
		res.writeHead(response.status, headers);
		if (response.body) {
			await new Promise<void>((resolve, reject) => {
				Readable.fromWeb(response.body as import("node:stream/web").ReadableStream)
					.on("error", reject)
					.pipe(res)
					.on("finish", resolve)
					.on("error", reject);
			});
		} else {
			res.end();
		}
	}
}

async function readBody(req: IncomingMessage): Promise<string | null> {
	if (req.method === "GET" || req.method === "HEAD") {
		// Java's @RequestBody is null for GET
		return null;
	}
	const chunks: Buffer[] = [];
	for await (const chunk of req) {
		chunks.push(chunk as Buffer);
	}
	if (chunks.length === 0) {
		return null;
	}
	return Buffer.concat(chunks).toString("utf8");
}

/** Java: TestDispatcher.convertQueryStringParamsToMap */
export function convertQueryStringParamsToMap(queryString: string | null | undefined): [string, string][] {
	if (!queryString) {
		return [];
	}
	return [...new URLSearchParams(queryString).entries()];
}

function contentTypeIs(req: IncomingMessage, type: string): boolean {
	const ct = (req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
	return ct === type;
}

/** Build the `requestParts` JSON object handed to test modules (Java: TestDispatcher.handle) */
export function buildRequestParts(req: IncomingMessage, url: URL, body: string | null): JsonObject {
	const requestParts: JsonObject = {};
	const headers = { ...(req.headers as Record<string, string | string[] | undefined>) };
	// upstream runs behind an nginx/apache proxy that adds the TLS details as headers (see the x-ssl-* handling
	// in TestDispatcher.logIncomingHttpRequest); the suite terminates TLS itself here, so it adds them
	const socket = req.socket as TLSSocket;
	if (typeof socket.getCipher === "function" && socket.encrypted) {
		headers["x-ssl-protocol"] ??= socket.getProtocol() ?? undefined;
		headers["x-ssl-cipher"] ??= socket.getCipher()?.name;
	}
	requestParts["headers"] = mapToJsonObject(headers, true);
	requestParts["query_string_params"] = mapToJsonObject(convertQueryStringParamsToMap(url.search.substring(1)), false);
	requestParts["method"] = (req.method ?? "GET").toUpperCase();
	requestParts["request_url"] = url.origin + url.pathname;
	if (body != null) {
		requestParts["body"] = body;
		if (contentTypeIs(req, "application/json")) {
			try {
				requestParts["body_json"] = parseJson(body);
			} catch (e) {
				requestParts["body_json_parse_error"] = (e as Error).message;
			}
		}
		if (contentTypeIs(req, "application/x-www-form-urlencoded")) {
			requestParts["body_form_params"] = mapToJsonObject(convertQueryStringParamsToMap(body), false);
		}
	}
	return requestParts;
}

function toIncomingRequest(req: IncomingMessage, url: URL): IncomingHttpRequest {
	const socket = req.socket as TLSSocket;
	const out: IncomingHttpRequest = {
		method: (req.method ?? "GET").toUpperCase(),
		url: url.toString(),
		headers: req.headers as Record<string, string | string[] | undefined>,
		remoteAddress: req.socket.remoteAddress,
	};
	if (typeof socket.getCipher === "function" && socket.encrypted) {
		const cert = socket.getPeerCertificate?.(true);
		out.tls = {
			cipher: socket.getCipher()?.name,
			version: socket.getProtocol() ?? undefined,
			clientCertificate: cert && cert.raw ? pem(cert.raw) : undefined,
		};
	}
	return out;
}

function pem(der: Buffer): string {
	return (
		"-----BEGIN CERTIFICATE-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----"
	);
}

function logIncomingHttpRequest(test: AbstractTestModule, path: string, requestParts: JsonObject): void {
	test
		.getEventLog()
		.log(
			test.getName(),
			args(
				"msg",
				"Incoming HTTP request to test instance " + test.getId(),
				"http",
				"incoming",
				"incoming_path",
				path,
				"incoming_query_string_params",
				requestParts["query_string_params"],
				"incoming_body_form_params",
				requestParts["body_form_params"],
				"incoming_method",
				requestParts["method"],
				"incoming_headers",
				requestParts["headers"],
				"incoming_body",
				requestParts["body"],
				"incoming_body_json",
				requestParts["body_json"],
				"incoming_body_json_parse_error",
				requestParts["body_json_parse_error"],
			),
		);
}

function logOutgoingHttpResponse(test: AbstractTestModule, path: string, response: Response): void {
	const headers: Record<string, string> = {};
	response.headers.forEach((v, k) => {
		headers[k] = v;
	});
	test
		.getEventLog()
		.log(
			test.getName(),
			args(
				"msg",
				"Response to HTTP request to test instance " + test.getId(),
				"http",
				"outgoing",
				"outgoing_path",
				path,
				"outgoing_status_code",
				response.status,
				"outgoing_headers",
				headers,
			),
		);
}
