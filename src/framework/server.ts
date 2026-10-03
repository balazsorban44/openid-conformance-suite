import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { TLSSocket } from "node:tls";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { AbstractTestModule } from "./AbstractTestModule.ts";
import { mapToJsonObject } from "./DataUtils.ts";
import { TestFailureException, TestInterruptedException } from "./exceptions.ts";
import { parseJson, type JsonObject } from "./json.ts";
import type { HttpSession, IncomingHttpRequest } from "./TestModule.ts";
import { jsonResponse } from "./views.ts";

export const TEST_PATH = "/test/"; // path for incoming test requests
export const TEST_MTLS_PATH = "/test-mtls/"; // path for incoming MTLS requests
const WELL_KNOWN = "/.well-known/";
const WEBFINGER_PATH = "/.well-known/webfinger";

/** The module handler serving each path prefix (well-known paths go to the module registered with `wellKnown`) */
const ROUTES = [
	{ prefix: TEST_PATH, handler: "handleHttp" },
	{ prefix: TEST_MTLS_PATH, handler: "handleHttpMtls" },
] as const;

type Handler = (typeof ROUTES)[number]["handler"] | "handleWellKnown";

/** Implemented by the RP test modules (Java: AbstractOIDCCClientTest) */
type WebfingerModule = AbstractTestModule & {
	handleWebfingerRequest?: (
		testName: string,
		prefix: string,
		resource: string,
		parts: JsonObject,
	) => Promise<JsonObject | Response | null>;
};

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
 *   /.well-known/webfinger  -> handleWebfingerRequest(...) of the RP test module named in `resource`
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
		if (pathname === WEBFINGER_PATH) {
			return send(res, await this.handleWebfinger(req, url));
		}
		const target = this.resolve(pathname);
		if (target instanceof Response) {
			return send(res, target);
		}
		const { test, handler, path } = target;
		const requestParts = buildRequestParts(req, url, await readBody(req));
		const incoming = toIncomingRequest(req, url);
		const session = this.session(req, res);
		logIncomingHttpRequest(test, pathname, requestParts);
		let response: Response;
		try {
			response = await test[handler](path, incoming, null, session, requestParts);
		} catch (e) {
			response = await errorResponse(test, e, "incoming HTTP request");
		}
		logOutgoingHttpResponse(test, pathname, response);
		await send(res, response);
	}

	/** The module and handler serving a request path (the rest of the path is handed to the module), or a 404 */
	private resolve(pathname: string): { test: AbstractTestModule; handler: Handler; path: string } | Response {
		if (pathname.startsWith(WELL_KNOWN)) {
			const test = this.wellKnownTestId ? this.tests.get(this.wellKnownTestId) : undefined;
			if (!test) {
				return jsonResponse({ error: "No running test serves " + pathname }, 404);
			}
			return { test, handler: "handleWellKnown", path: pathname };
		}
		const route = ROUTES.find((r) => pathname.startsWith(r.prefix));
		if (!route) {
			return jsonResponse({ error: "not found" }, 404);
		}
		const pathParts = pathname.substring(route.prefix.length).split("/");
		let testId = pathParts.shift() ?? "";
		if (testId === "a") {
			const alias = decodeURIComponent(pathParts.shift() ?? "");
			const id = this.aliases.get(alias);
			if (!id) {
				return jsonResponse({ error: "No test found with alias '" + alias + "'" }, 404);
			}
			testId = id;
		}
		const test = this.tests.get(testId);
		if (!test) {
			return jsonResponse({ error: "No running test with test id '" + testId + "'" }, 404);
		}
		return { test, handler: route.handler, path: pathParts.join("/") };
	}

	/** Port of TestDispatcher.handleWellKnownWebFingerRequest: routes webfinger to the RP test module named in `resource` */
	private async handleWebfinger(req: IncomingMessage, url: URL): Promise<Response> {
		const resource = url.searchParams.get("resource");
		if (resource == null) {
			// https://tools.ietf.org/html/rfc7033#section-4
			return jsonResponse({ error: "resource parameter missing" }, 400);
		}
		const acct = /^acct:([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)@.*$/i.exec(resource);
		const match = acct ?? /^https?:\/\/.*\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)$/i.exec(resource);
		if (!match) {
			return new Response(null, { status: 400 });
		}
		const resourcePrefix = acct ? "acct" : "https";
		const [, alias, testName] = match;
		const testId = this.aliases.get(alias) ?? alias;
		const test = this.tests.get(testId) as WebfingerModule | undefined;
		if (!test) {
			return jsonResponse({ error: "no running test for test id '" + testId + "' from alias '" + alias + "'" }, 404);
		}
		if (typeof test.handleWebfingerRequest !== "function") {
			return new Response(null, { status: 400 });
		}
		const requestParts: JsonObject = {
			headers: mapToJsonObject(req.headers as Record<string, string | string[] | undefined>, true),
			query_string_params: mapToJsonObject(convertQueryStringParamsToMap(url.search.substring(1)), false),
			method: (req.method ?? "GET").toUpperCase(),
		};
		logIncomingHttpRequest(test, WEBFINGER_PATH, requestParts);
		try {
			if (test.getStatus() === "CREATED") {
				throw new TestFailureException(
					test.getId(),
					"Please wait for the test to be in WAITING state. The current status is CREATED",
				);
			}
			const response = await test.handleWebfingerRequest(testName, resourcePrefix, resource, requestParts);
			const out = response instanceof Response ? response : jsonResponse(response ?? {}, 200);
			logOutgoingHttpResponse(test, WEBFINGER_PATH, out);
			return out;
		} catch (e) {
			return errorResponse(test, e, "incoming webfinger request");
		}
	}
}

/**
 * Java: TestDispatcher's @ExceptionHandler. Releases the test's lock, hands the failure to the test and answers
 * with an error response.
 */
async function errorResponse(test: AbstractTestModule, e: unknown, source: string): Promise<Response> {
	test.forceReleaseLock();
	const error = e instanceof TestInterruptedException ? e : new TestFailureException(test.getId(), e);
	await test.handleException(error, source);
	const tfe = error instanceof TestFailureException ? error : null;
	const body: JsonObject = { error: tfe?.getError() ?? error.message };
	if (tfe?.getErrorDescription()) {
		body["error_description"] = tfe.getErrorDescription();
	}
	return jsonResponse(body, 400);
}

async function send(res: ServerResponse, response: Response): Promise<void> {
	const body = response.body ? Buffer.from(await response.arrayBuffer()) : undefined;
	const headers: Record<string, string | string[]> = Object.fromEntries(response.headers);
	// the session cookie set by session() comes first, then the module's own cookies (one header each)
	const setCookie = [res.getHeader("set-cookie") ?? [], response.headers.getSetCookie()].flat().map(String);
	if (setCookie.length > 0) {
		headers["set-cookie"] = setCookie;
	}
	res.writeHead(response.status, headers);
	res.end(body);
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

/** The request's socket when the suite terminated TLS for it */
function tlsSocket(req: IncomingMessage): TLSSocket | null {
	const socket = req.socket as TLSSocket;
	return typeof socket.getCipher === "function" && socket.encrypted ? socket : null;
}

/** Build the `requestParts` JSON object handed to test modules (Java: TestDispatcher.handle) */
export function buildRequestParts(req: IncomingMessage, url: URL, body: string | null): JsonObject {
	const headers = { ...(req.headers as Record<string, string | string[] | undefined>) };
	// upstream runs behind an nginx/apache proxy that adds the TLS details as headers (see the x-ssl-* handling
	// in TestDispatcher.logIncomingHttpRequest); the suite terminates TLS itself here, so it adds them
	const tls = tlsSocket(req);
	if (tls) {
		headers["x-ssl-protocol"] ??= tls.getProtocol() ?? undefined;
		headers["x-ssl-cipher"] ??= tls.getCipher()?.name;
	}
	const requestParts: JsonObject = {
		headers: mapToJsonObject(headers, true),
		query_string_params: mapToJsonObject(convertQueryStringParamsToMap(url.search.substring(1)), false),
		method: (req.method ?? "GET").toUpperCase(),
		request_url: url.origin + url.pathname,
	};
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
	const out: IncomingHttpRequest = {
		method: (req.method ?? "GET").toUpperCase(),
		url: url.toString(),
		headers: req.headers as Record<string, string | string[] | undefined>,
		remoteAddress: req.socket.remoteAddress,
	};
	const tls = tlsSocket(req);
	if (tls) {
		const cert = tls.getPeerCertificate?.(true);
		out.tls = {
			cipher: tls.getCipher()?.name,
			version: tls.getProtocol() ?? undefined,
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
	test.getEventLog().log(test.getName(), {
		msg: "Incoming HTTP request to test instance " + test.getId(),
		http: "incoming",
		incoming_path: path,
		incoming_query_string_params: requestParts["query_string_params"],
		incoming_body_form_params: requestParts["body_form_params"],
		incoming_method: requestParts["method"],
		incoming_headers: requestParts["headers"],
		incoming_body: requestParts["body"],
		incoming_body_json: requestParts["body_json"],
		incoming_body_json_parse_error: requestParts["body_json_parse_error"],
	});
}

function logOutgoingHttpResponse(test: AbstractTestModule, path: string, response: Response): void {
	test.getEventLog().log(test.getName(), {
		msg: "Response to HTTP request to test instance " + test.getId(),
		http: "outgoing",
		outgoing_path: path,
		outgoing_status_code: response.status,
		outgoing_headers: Object.fromEntries(response.headers),
	});
}
