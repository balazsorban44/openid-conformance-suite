/**
 * The suite's own HTTP(S) server (upstream runner/TestDispatcher): the redirect_uri, the implicit-submit endpoint,
 * the emulated OP's endpoints for RP tests, `/.well-known/...` documents. One server per test, on a free port.
 *
 *   const server = await startServer({ tls, log, testName: "oidcc-server", alias: "my-op" });
 *   server.baseUrl                                   // https://localhost:41234/test/a/my-op
 *   const callback = server.waitFor("callback", () => htmlResponse(page));   // register before the request is sent
 *   ... drive the browser ...
 *   const req = await callback;                      // req.query, req.headers, req.method, req.bodyForm ...
 *   server.on("token", (req) => Response.json({...}));   // a persistent endpoint (RP tests)
 *   await server.close();
 *
 * Every request to a test path is logged as upstream does ("Incoming HTTP request to test instance <id>" /
 * "Response to HTTP request to test instance <id>", under the test module's name) and handed to the handler as
 * {@link IncomingRequest} (upstream's `requestParts`: lower-cased headers with repeated headers as arrays,
 * x-ssl-protocol/x-ssl-cipher when the suite terminated TLS, query_string_params, method, request_url, body,
 * body_json / body_form_params).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { TLSSocket } from "node:tls";
import { headersToJson } from "./http.ts";
import type { EventLog } from "./log.ts";

export const TEST_PATH = "/test/";
const WELL_KNOWN = "/.well-known/";

/** An incoming request in upstream's `requestParts` shape */
export interface IncomingRequest {
	headers: Record<string, string | string[]>;
	query_string_params: Record<string, string | string[]>;
	method: string;
	request_url: string;
	body?: string;
	body_json?: unknown;
	body_json_parse_error?: string;
	body_form_params?: Record<string, string | string[]>;
	/** The path below the test's base url (e.g. "callback"), or the full path for /.well-known/ requests */
	path: string;
	/** TLS details when the suite terminated TLS (client certificate as PEM when one was presented) */
	tls?: { cipher?: string; version?: string; clientCertificate?: string };
}

export type Handler = (req: IncomingRequest) => Response | Promise<Response>;

export interface TestServer {
	/** The URL other parties use for this test (upstream base_url): <origin>/test/a/<alias> */
	readonly baseUrl: string;
	readonly origin: string;
	/** A persistent handler for `path` (relative to baseUrl, or an absolute /.well-known/ path) */
	on(path: string, handler: Handler): void;
	off(path: string): void;
	/**
	 * Resolves with the next request to `path` once `respond` answered it. Register before triggering the request.
	 * Rejects after `timeoutSeconds` (default 60) or when `signal` aborts.
	 */
	waitFor(
		path: string,
		respond?: Response | Handler,
		opts?: { timeoutSeconds?: number; signal?: AbortSignal },
	): Promise<IncomingRequest>;
	close(): Promise<void>;
}

export interface ServerOptions {
	log: EventLog;
	/** The `src` of the incoming/outgoing entries (the test module name) */
	testName: string;
	/** config `alias`; the base url is /test/a/<alias> (default: the test id) */
	alias?: string | null;
	tls?: { cert: string; key: string; ca?: string; requestCert?: boolean };
	host?: string;
	port?: number;
	/** How others reach the server, when not http(s)://localhost:<port> */
	externalUrl?: string;
}

interface Waiter {
	respond: Response | Handler;
	resolve: (req: IncomingRequest) => void;
	reject: (e: Error) => void;
}

export async function startServer(opts: ServerOptions): Promise<TestServer> {
	const handlers = new Map<string, Handler>();
	const waiters = new Map<string, Waiter[]>();
	const log = opts.log;
	const prefix = TEST_PATH + (opts.alias ? "a/" + encodeURIComponent(opts.alias) : log.testId);

	const listener = (req: IncomingMessage, res: ServerResponse) => {
		handle(req, res).catch((e: unknown) => {
			if (!res.headersSent) {
				res.writeHead(500, { "content-type": "application/json" });
			}
			res.end(JSON.stringify({ error: (e as Error).message ?? String(e) }));
		});
	};
	const server: Server = opts.tls
		? createHttpsServer(
				{
					cert: opts.tls.cert,
					key: opts.tls.key,
					ca: opts.tls.ca,
					requestCert: opts.tls.requestCert ?? false,
					rejectUnauthorized: false,
				},
				listener,
			)
		: createServer(listener);
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(opts.port ?? 0, opts.host ?? "127.0.0.1", () => resolve());
	});
	const port = (server.address() as AddressInfo).port;
	const origin = opts.externalUrl?.replace(/\/$/, "") ?? `${opts.tls ? "https" : "http"}://localhost:${port}`;

	async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
		const url = new URL(req.url ?? "/", origin);
		const pathname = url.pathname;
		let path: string;
		if (pathname.startsWith(WELL_KNOWN)) {
			path = pathname;
		} else if (pathname.startsWith(prefix + "/")) {
			path = pathname.substring(prefix.length + 1);
		} else {
			return send(res, Response.json({ error: "No running test serves " + pathname }, { status: 404 }));
		}
		const parts = buildRequestParts(req, url, await readBody(req), path);
		logIncoming(pathname, parts);
		let response: Response;
		const waiter = waiters.get(path)?.shift();
		try {
			if (waiter) {
				response = typeof waiter.respond === "function" ? await waiter.respond(parts) : waiter.respond.clone();
			} else {
				const handler = handlers.get(path);
				response = handler
					? await handler(parts)
					: Response.json({ error: "The test is not expecting a request to " + pathname }, { status: 404 });
			}
		} catch (e) {
			waiter?.reject(e as Error);
			response = Response.json({ error: (e as Error).message }, { status: 400 });
		}
		logOutgoing(pathname, response);
		await send(res, response);
		waiter?.resolve(parts);
	}

	function logIncoming(path: string, parts: IncomingRequest): void {
		log.log(opts.testName, {
			msg: "Incoming HTTP request to test instance " + log.testId,
			http: "incoming",
			incoming_path: path,
			incoming_query_string_params: parts.query_string_params,
			incoming_body_form_params: parts.body_form_params,
			incoming_method: parts.method,
			incoming_headers: parts.headers,
			incoming_body: parts.body,
			incoming_body_json: parts.body_json,
			incoming_body_json_parse_error: parts.body_json_parse_error,
		});
	}

	function logOutgoing(path: string, response: Response): void {
		log.log(opts.testName, {
			msg: "Response to HTTP request to test instance " + log.testId,
			http: "outgoing",
			outgoing_path: path,
			outgoing_status_code: response.status,
			outgoing_headers: Object.fromEntries(response.headers),
		});
	}

	return {
		baseUrl: origin + prefix,
		origin,
		on(path, handler) {
			handlers.set(path, handler);
		},
		off(path) {
			handlers.delete(path);
		},
		waitFor(path, respond = new Response(null, { status: 204 }), { timeoutSeconds = 60, signal } = {}) {
			const { promise, resolve, reject } = Promise.withResolvers<IncomingRequest>();
			const list = waiters.get(path) ?? [];
			const waiter: Waiter = { respond, resolve, reject };
			list.push(waiter);
			waiters.set(path, list);
			const remove = () => {
				const i = list.indexOf(waiter);
				if (i !== -1) {
					list.splice(i, 1);
				}
			};
			const timer = setTimeout(() => {
				remove();
				reject(new Error(`Timed out after ${timeoutSeconds} seconds waiting for a request to ${prefix}/${path}`));
			}, timeoutSeconds * 1000);
			const onAbort = () => {
				remove();
				reject(signal?.reason instanceof Error ? signal.reason : new Error("aborted"));
			};
			signal?.addEventListener("abort", onAbort, { once: true });
			return promise.finally(() => {
				clearTimeout(timer);
				signal?.removeEventListener("abort", onAbort);
			});
		},
		async close() {
			for (const list of waiters.values()) {
				for (const w of list) {
					w.reject(new Error("server closed"));
				}
			}
			waiters.clear();
			server.closeAllConnections();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		},
	};
}

async function send(res: ServerResponse, response: Response): Promise<void> {
	const body = response.body ? Buffer.from(await response.arrayBuffer()) : undefined;
	const headers: Record<string, string | string[]> = Object.fromEntries(response.headers);
	const setCookie = response.headers.getSetCookie();
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
	return chunks.length === 0 ? null : Buffer.concat(chunks).toString("utf8");
}

/** Repeated parameters become arrays (upstream TestDispatcher.convertQueryStringParamsToMap + mapToJsonObject) */
function paramsToJson(query: string): Record<string, string | string[]> {
	return headersToJson([...new URLSearchParams(query).entries()], false);
}

function contentTypeIs(req: IncomingMessage, type: string): boolean {
	return (req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase() === type;
}

/** The request in upstream's `requestParts` shape (TestDispatcher.handle) */
export function buildRequestParts(req: IncomingMessage, url: URL, body: string | null, path: string): IncomingRequest {
	const headers = { ...(req.headers as Record<string, string | string[] | undefined>) };
	// upstream runs behind a TLS-terminating proxy that adds the TLS details as headers; this server terminates TLS
	// itself, so it adds them
	const socket = req.socket as TLSSocket;
	const tls = typeof socket.getCipher === "function" && socket.encrypted ? socket : null;
	if (tls) {
		headers["x-ssl-protocol"] ??= tls.getProtocol() ?? undefined;
		headers["x-ssl-cipher"] ??= tls.getCipher()?.name;
	}
	const parts: IncomingRequest = {
		headers: headersToJson(headers, true),
		query_string_params: paramsToJson(url.search.substring(1)),
		method: (req.method ?? "GET").toUpperCase(),
		request_url: url.origin + url.pathname,
		path,
	};
	if (body != null) {
		parts.body = body;
		if (contentTypeIs(req, "application/json")) {
			try {
				parts.body_json = JSON.parse(body);
			} catch (e) {
				parts.body_json_parse_error = (e as Error).message;
			}
		}
		if (contentTypeIs(req, "application/x-www-form-urlencoded")) {
			parts.body_form_params = paramsToJson(body);
		}
	}
	if (tls) {
		const cert = tls.getPeerCertificate?.(true);
		parts.tls = {
			cipher: tls.getCipher()?.name,
			version: tls.getProtocol() ?? undefined,
			clientCertificate:
				cert && cert.raw
					? `-----BEGIN CERTIFICATE-----\n${cert.raw.toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----`
					: undefined,
		};
	}
	return parts;
}

export function htmlResponse(html: string, status = 200, headers?: Record<string, string>): Response {
	return new Response(html, { status, headers: { "content-type": "text/html;charset=UTF-8", ...headers } });
}
