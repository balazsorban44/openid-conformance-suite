import { Agent, type Dispatcher } from "undici";
import { mapToJsonObject, type LogArgs } from "./DataUtils.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import type { JsonObject } from "./json.ts";
import type { TestLockManager } from "./TestLockManager.ts";

/**
 * Outbound HTTP for conditions. Port of the behaviour of AbstractCondition.createRestTemplate() +
 * logging/LoggingRequestInterceptor.java:
 *
 *  - every request and response is written to the test log ("HTTP request" / "HTTP response" entries)
 *  - redirects are NOT followed, there are no retries, all TLS certificates are trusted (the suite is
 *    testing protocol behaviour, not PKI), TLS versions are restricted to 1.2/1.3 unless asked otherwise
 *  - the test lock is released while the network I/O happens (see TestLockManager)
 *  - no HTTP status code is treated as an error (Spring's RestTemplate throws on 4xx/5xx by default;
 *    callers that relied on that must check `response.status` themselves)
 *  - network failures throw HttpClientException
 */

export interface HttpRequest {
	url: string;
	method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
	headers?: Headers | Record<string, string | string[]> | JsonObject | null;
	/** A string body is sent as-is; URLSearchParams as application/x-www-form-urlencoded; an object as JSON */
	body?: string | URLSearchParams | Uint8Array | JsonObject | null;
}

export interface HttpResponse {
	status: number;
	statusText: string;
	headers: Headers;
	/** The response body decoded as UTF-8 text (null if there was no body at all) */
	body: string | null;
	bodyBytes: Uint8Array;
	/** The final request URL */
	url: string;
}

export class HttpClientException extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "HttpClientException";
	}
}

export interface MutualTlsConfig {
	cert: string;
	key: string;
	ca?: string;
}

export interface HttpClientOptions {
	/** The log source (normally the condition class name) */
	source: string;
	log: TestInstanceEventLog;
	lockManager?: TestLockManager | null;
	/** mTLS client certificate configuration (the environment's "mutual_tls_authentication" object) */
	mutualTls?: JsonObject | null;
	restrictAllowedTLSVersions?: boolean;
	timeoutSeconds?: number;
}

export class HttpClient {
	private readonly opts: HttpClientOptions;
	private readonly dispatcher: Dispatcher;

	constructor(opts: HttpClientOptions) {
		this.opts = opts;
		const timeout = (opts.timeoutSeconds ?? 60) * 1000;
		const mtls = opts.mutualTls;
		this.dispatcher = new Agent({
			connect: {
				rejectUnauthorized: false,
				minVersion: opts.restrictAllowedTLSVersions === false ? undefined : "TLSv1.2",
				timeout,
				cert: typeof mtls?.["cert"] === "string" ? (mtls["cert"] as string) : undefined,
				key: typeof mtls?.["key"] === "string" ? (mtls["key"] as string) : undefined,
			},
			headersTimeout: timeout,
			bodyTimeout: timeout,
			// a fresh connection per call is deliberate upstream ("No HTTP connection pooling")
			pipelining: 0,
			connections: 1,
		});
	}

	async exchange(req: HttpRequest): Promise<HttpResponse> {
		const method = req.method ?? "GET";
		const headers = new Headers();
		if (req.headers instanceof Headers) {
			req.headers.forEach((v, k) => headers.append(k, v));
		} else if (req.headers) {
			for (const [k, v] of Object.entries(req.headers)) {
				if (Array.isArray(v)) {
					for (const x of v) {
						headers.append(k, String(x));
					}
				} else if (v != null) {
					headers.set(k, String(v));
				}
			}
		}
		let body: string | Uint8Array | undefined;
		if (req.body == null) {
			body = undefined;
		} else if (typeof req.body === "string" || req.body instanceof Uint8Array) {
			body = req.body;
		} else if (req.body instanceof URLSearchParams) {
			body = req.body.toString();
			if (!headers.has("content-type")) {
				headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
			}
		} else {
			body = JSON.stringify(req.body);
			if (!headers.has("content-type")) {
				headers.set("content-type", "application/json");
			}
		}
		if (body !== undefined && !headers.has("content-length")) {
			headers.set("content-length", String(typeof body === "string" ? Buffer.byteLength(body) : body.byteLength));
		}
		if (!headers.has("accept-encoding")) {
			// avoid transparent decompression surprises in the logged body
			headers.set("accept-encoding", "identity");
		}
		if (!headers.has("user-agent")) {
			headers.set("user-agent", "openid-conformance-suite");
		}

		// Log request while lock is held for deterministic ordering
		const reqLog: LogArgs = {
			request_uri: req.url,
			request_method: method,
			request_headers: mapToJsonObject(headers, false),
		};
		if (body !== undefined) {
			addBodyProperty(reqLog, "request_body", typeof body === "string" ? Buffer.from(body) : body);
		}
		reqLog["msg"] = "HTTP request";
		reqLog["http"] = "request";
		if (this.opts.mutualTls) {
			reqLog["request_mutual_tls"] = this.opts.mutualTls;
		}
		this.opts.log.log(this.opts.source, reqLog);

		const lockManager = this.opts.lockManager;
		let response: Response;
		let bodyBytes: Uint8Array;
		let bodyException: Error | null = null;
		if (lockManager) {
			await lockManager.releaseLock();
		}
		try {
			try {
				response = await fetch(req.url, {
					method,
					headers,
					body: body as string | Uint8Array | undefined,
					redirect: "manual",
					dispatcher: this.dispatcher,
					signal: AbortSignal.timeout((this.opts.timeoutSeconds ?? 60) * 1000),
				} as RequestInit);
			} catch (e) {
				const cause = (e as Error).cause;
				const detail = cause instanceof Error ? cause.message : (e as Error).message;
				throw new HttpClientException(`I/O error on ${method} request for "${req.url}": ${detail}`, { cause: e });
			}
			try {
				bodyBytes = new Uint8Array(await response.arrayBuffer());
			} catch (e) {
				bodyBytes = new Uint8Array();
				bodyException = e as Error;
			}
		} finally {
			if (lockManager) {
				await lockManager.reacquireLock();
			}
		}

		const resLog: LogArgs = {
			response_status_code: String(response.status),
			response_status_text: response.statusText,
			response_headers: mapToJsonObject(response.headers, true),
		};
		addBodyProperty(resLog, "response_body", bodyBytes);
		resLog["msg"] = "HTTP response";
		resLog["http"] = "response";
		if (bodyException) {
			resLog["exception_reading_body"] = bodyException.message;
		}
		this.opts.log.log(this.opts.source, resLog);

		return {
			status: response.status,
			statusText: response.statusText,
			headers: response.headers,
			body: decodeBody(bodyBytes),
			bodyBytes,
			url: response.url || req.url,
		};
	}

	close(): Promise<void> {
		return this.dispatcher.close();
	}
}

function decodeBody(bytes: Uint8Array): string | null {
	if (bytes.byteLength === 0) {
		return null;
	}
	return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

const PREVIEW_BYTES = 32;

/**
 * Adds the body under the given key if it is text; a binary body is replaced with a "<key>_omitted" note.
 * Decided from the bytes themselves (strict UTF-8 decode plus a control-character scan), never from the
 * Content-Type header - the suite regularly deals with mislabelled responses.
 */
export function addBodyProperty(o: LogArgs, key: string, body: Uint8Array): void {
	if (body.byteLength === 0) {
		o[key] = "";
		return;
	}
	let text: string;
	try {
		text = new TextDecoder("utf-8", { fatal: true }).decode(body);
	} catch {
		addBinaryBodyNote(o, key, body, 0, "not valid UTF-8");
		return;
	}
	for (let i = 0; i < text.length; i++) {
		const c = text.charCodeAt(i);
		if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) {
			const byteOffset = Buffer.byteLength(text.substring(0, i));
			addBinaryBodyNote(
				o,
				key,
				body,
				byteOffset,
				`decodes as UTF-8 but contains control character U+${c.toString(16).toUpperCase().padStart(4, "0")} at character offset ${i} (byte offset ${byteOffset})`,
			);
			return;
		}
	}
	o[key] = text;
}

function addBinaryBodyNote(o: LogArgs, key: string, body: Uint8Array, badOffset: number, reason: string): void {
	o[key + "_omitted"] = `binary content, ${body.byteLength} bytes - not shown (${reason})`;
	o[key + "_first_bytes"] = escapeBytes(body, 0, PREVIEW_BYTES);
	const from = Math.max(0, badOffset - PREVIEW_BYTES / 2);
	const to = Math.min(body.byteLength, badOffset + PREVIEW_BYTES / 2);
	if (to > PREVIEW_BYTES) {
		o[key + "_bytes_around_offset"] = `bytes ${from}..${to - 1}: ${escapeBytes(body, from, to)}`;
	}
}

function escapeBytes(body: Uint8Array, from: number, to: number): string {
	let sb = "";
	for (let i = from; i < Math.min(to, body.byteLength); i++) {
		const b = body[i];
		if (b === 0x5c) {
			sb += "\\\\";
		} else if (b >= 0x20 && b <= 0x7e) {
			sb += String.fromCharCode(b);
		} else {
			sb += "\\x" + b.toString(16).padStart(2, "0");
		}
	}
	return sb;
}
