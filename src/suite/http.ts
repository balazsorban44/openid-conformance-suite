/**
 * Outbound HTTP for checks: upstream's AbstractCondition.createRestTemplate() + LoggingRequestInterceptor.
 *
 *  - every request and response is logged under the calling condition's name ("HTTP request" / "HTTP response"
 *    entries with request_uri, request_method, request_headers, request_body / response_status_code (a string),
 *    response_status_text, response_headers, response_body)
 *  - redirects are not followed, no status is an error (callers check `status`), all TLS certificates are trusted
 *    (the suite tests protocol behaviour, not PKI), TLS 1.2+ only, no connection reuse
 *  - network failures throw {@link HttpError}
 */
// called through the module objects (not named imports) so that interceptors such as MSW in unit tests see the calls
import http, { type IncomingMessage } from "node:http";
import https from "node:https";
import { currentLog, type LogFields } from "./log.ts";

export interface HttpRequest {
	url: string;
	method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
	/** Header values; arrays send the header several times */
	headers?: Headers | Record<string, string | string[]>;
	/** A string is sent as is; URLSearchParams as application/x-www-form-urlencoded; an object as JSON */
	body?: string | URLSearchParams | Uint8Array | Record<string, unknown> | null;
	timeoutSeconds?: number;
	/** mTLS client certificate (PEM) */
	clientCertificate?: { cert: string; key: string };
}

export interface HttpResponse {
	status: number;
	statusText: string;
	headers: Headers;
	/** The body decoded as UTF-8, null when there was none */
	body: string | null;
	bodyBytes: Uint8Array;
	url: string;
}

export class HttpError extends Error {
	override name = "HttpError";
}

/** Sends `req` and logs it under `source` (the upstream condition name making the call) */
export async function request(source: string, req: HttpRequest): Promise<HttpResponse> {
	const log = currentLog();
	const method = req.method ?? "GET";
	const headers = toHeaders(req.headers);
	const body = encodeBody(req.body, headers);
	if (body !== undefined && !headers.has("content-length")) {
		headers.set("content-length", String(typeof body === "string" ? Buffer.byteLength(body) : body.byteLength));
	}
	if (!headers.has("accept-encoding")) {
		// no transparent decompression: the logged body is what the server sent
		headers.set("accept-encoding", "identity");
	}
	if (!headers.has("user-agent")) {
		headers.set("user-agent", "openid-conformance-suite");
	}

	const reqLog: LogFields = {
		request_uri: req.url,
		request_method: method,
		request_headers: headersToJson(headers, false),
	};
	if (body !== undefined) {
		addBodyProperty(reqLog, "request_body", typeof body === "string" ? Buffer.from(body) : body);
	}
	reqLog["msg"] = "HTTP request";
	reqLog["http"] = "request";
	if (req.clientCertificate) {
		reqLog["request_mutual_tls"] = { cert: req.clientCertificate.cert };
	}
	log.log(source, reqLog);

	let res: IncomingMessage;
	let bytes: Uint8Array;
	let bodyError: Error | null = null;
	try {
		res = await send(req, method, headers, body);
	} catch (e) {
		throw new HttpError(`I/O error on ${method} request for "${req.url}": ${(e as Error).message}`, { cause: e });
	}
	try {
		const chunks: Buffer[] = [];
		for await (const chunk of res) {
			chunks.push(chunk as Buffer);
		}
		bytes = new Uint8Array(Buffer.concat(chunks));
	} catch (e) {
		bytes = new Uint8Array();
		bodyError = e as Error;
	}
	const responseHeaders = new Headers();
	for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
		responseHeaders.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
	}
	const result: HttpResponse = {
		status: res.statusCode ?? 0,
		statusText: res.statusMessage ?? "",
		headers: responseHeaders,
		body: bytes.byteLength === 0 ? null : new TextDecoder("utf-8", { fatal: false }).decode(bytes),
		bodyBytes: bytes,
		url: req.url,
	};

	const resLog: LogFields = {
		response_status_code: String(result.status),
		response_status_text: result.statusText,
		response_headers: headersToJson(result.headers, true),
	};
	addBodyProperty(resLog, "response_body", bytes);
	resLog["msg"] = "HTTP response";
	resLog["http"] = "response";
	if (bodyError) {
		resLog["exception_reading_body"] = bodyError.message;
	}
	log.log(source, resLog);
	return result;
}

/**
 * One request on a fresh connection (no keep-alive agent: upstream does not pool connections), redirects not
 * followed, any certificate accepted, TLS 1.2 or newer.
 */
function send(
	req: HttpRequest,
	method: string,
	headers: Headers,
	body: string | Uint8Array | undefined,
): Promise<IncomingMessage> {
	const url = new URL(req.url);
	const timeoutMs = (req.timeoutSeconds ?? 60) * 1000;
	const outgoing: Record<string, string | string[]> = {};
	headers.forEach((v, k) => {
		outgoing[k] = k === "set-cookie" ? headers.getSetCookie() : v;
	});
	// Headers joins repeated values with ", "; an array value is sent as that many header lines
	if (req.headers != null && !(req.headers instanceof Headers)) {
		for (const [k, v] of Object.entries(req.headers)) {
			if (Array.isArray(v)) {
				outgoing[k.toLowerCase()] = v;
			}
		}
	}
	const options = {
		method,
		headers: outgoing,
		agent: false as const,
		timeout: timeoutMs,
		rejectUnauthorized: false,
		minVersion: "TLSv1.2" as const,
		cert: req.clientCertificate?.cert,
		key: req.clientCertificate?.key,
	};
	return new Promise((resolve, reject) => {
		const r = url.protocol === "https:" ? https.request(url, options, resolve) : http.request(url, options, resolve);
		r.on("error", reject);
		r.on("timeout", () => r.destroy(new Error(`timed out after ${timeoutMs / 1000} seconds`)));
		r.end(body);
	});
}

function toHeaders(h: HttpRequest["headers"]): Headers {
	if (h instanceof Headers) {
		return new Headers(h);
	}
	const headers = new Headers();
	for (const [k, v] of Object.entries(h ?? {})) {
		for (const x of Array.isArray(v) ? v : [v]) {
			headers.append(k, x);
		}
	}
	return headers;
}

/** The request body as sent; sets the content-type of form and JSON bodies unless the caller did */
function encodeBody(body: HttpRequest["body"], headers: Headers): string | Uint8Array | undefined {
	if (body == null) {
		return undefined;
	}
	if (typeof body === "string" || body instanceof Uint8Array) {
		return body;
	}
	const [encoded, contentType] =
		body instanceof URLSearchParams
			? [body.toString(), "application/x-www-form-urlencoded;charset=UTF-8"]
			: [JSON.stringify(body), "application/json"];
	if (!headers.has("content-type")) {
		headers.set("content-type", contentType);
	}
	return encoded;
}

/**
 * Headers as a JSON object (upstream mapToJsonObject): keys optionally lower-cased, a header present several times
 * becomes an array (set-cookie values are kept apart).
 */
export function headersToJson(
	headers: Headers | Record<string, string | string[] | undefined> | Iterable<[string, string]>,
	lowercase: boolean,
): Record<string, string | string[]> {
	const multi = new Map<string, string[]>();
	let entries: Iterable<[string, string | string[] | undefined]>;
	if (headers instanceof Headers) {
		const list: [string, string][] = [];
		headers.forEach((value, key) => list.push([key, value]));
		const setCookie = headers.getSetCookie();
		entries =
			setCookie.length <= 1
				? list
				: [...list.filter(([k]) => k !== "set-cookie"), ...setCookie.map((c): [string, string] => ["set-cookie", c])];
	} else {
		entries = Symbol.iterator in headers ? (headers as Iterable<[string, string]>) : Object.entries(headers);
	}
	for (const [rawKey, value] of entries) {
		if (value === undefined) {
			continue;
		}
		const key = lowercase ? rawKey.toLowerCase() : rawKey;
		multi.set(key, (multi.get(key) ?? []).concat(value));
	}
	const o: Record<string, string | string[]> = {};
	for (const [key, values] of multi) {
		o[key] = values.length > 1 ? values : values[0];
	}
	return o;
}

/** A response as upstream stores it for an endpoint (convertResponseForEnvironment): status, name, headers, body */
export interface EndpointResponse {
	status: number;
	endpoint_name: string;
	headers: Record<string, string | string[]>;
	body: string | null;
	/** The body parsed as JSON when it is an object or an array */
	body_json?: unknown;
}

/**
 * The response in upstream's environment shape (convertJsonResponseForEnvironment with allowParseFailure):
 * `body_json` is set when the body is a JSON object or array.
 */
export function endpointResponse(endpointName: string, res: HttpResponse): EndpointResponse {
	const out: EndpointResponse = {
		status: res.status,
		endpoint_name: endpointName,
		headers: headersToJson(res.headers, true),
		body: res.body,
	};
	const json = jsonBody(res);
	if (json.ok && typeof json.value === "object" && json.value !== null) {
		out.body_json = json.value;
	}
	return out;
}

/** The body parsed as JSON: `{ ok: true, value }` or `{ ok: false, error }` (empty body: error "empty") */
export function jsonBody(res: HttpResponse): { ok: true; value: unknown } | { ok: false; error: string } {
	if (res.body == null || res.body === "") {
		return { ok: false, error: "empty" };
	}
	try {
		return { ok: true, value: JSON.parse(res.body) };
	} catch (e) {
		return { ok: false, error: (e as Error).message };
	}
}

const PREVIEW_BYTES = 32;

/**
 * Adds the body under `key` if it is text; a binary body is replaced with a "<key>_omitted" note. Decided from the
 * bytes (strict UTF-8 decode plus a control-character scan), never from the Content-Type header.
 */
export function addBodyProperty(o: LogFields, key: string, body: Uint8Array): void {
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

function addBinaryBodyNote(o: LogFields, key: string, body: Uint8Array, badOffset: number, reason: string): void {
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
