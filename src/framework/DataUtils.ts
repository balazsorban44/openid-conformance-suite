import { ConditionResult } from "./Condition.ts";
import type { JsonObject } from "./json.ts";

/**
 * Port of testmodule/DataUtils.java (static helpers rather than a mixin interface).
 *
 * Java `Map<String, Object>` and `JsonObject` both map to `LogArgs`/`JsonObject` here.
 */
export type LogArgs = Record<string, unknown>;

export const DATAUTILS_MEDIATYPE_APPLICATION_JWT_UTF8 = "application/jwt;charset=UTF-8";
export const DATAUTILS_MEDIATYPE_APPLICATION_JOSE = "application/jose";
export const DATAUTILS_MEDIATYPE_APPLICATION_JWT = "application/jwt";
// as per https://www.rfc-editor.org/rfc/rfc9101.html#section-4
export const DATAUTILS_MEDIATYPE_APPLICATION_OAUTH_OAUTHZ_REQ_JWT = "application/oauth-authz-req+jwt";

/**
 * Java: args("key", value, "key2", value2, ...) -> Map<String, Object>
 */
export function args(...a: unknown[]): LogArgs {
	if (a.length % 2 !== 0) {
		throw new Error("Need an even and nonzero number of arguments");
	}
	const m: LogArgs = {};
	for (let i = 0; i < a.length; i += 2) {
		m[a[i] as string] = a[i + 1];
	}
	return m;
}

/**
 * Utility function to convert HTTP headers (or a multi-value map) to a JsonObject for storage.
 * Duplicated headers become an array of values.
 */
export function mapToJsonObject(
	headers: Headers | Record<string, string | string[] | undefined> | Iterable<[string, string]>,
	lowercase: boolean,
): JsonObject {
	const multi = new Map<string, string[]>();
	for (const [rawKey, value] of headerEntries(headers)) {
		if (value === undefined) {
			continue;
		}
		const key = lowercase ? rawKey.toLowerCase() : rawKey;
		multi.set(key, (multi.get(key) ?? []).concat(value));
	}
	const o: JsonObject = {};
	for (const [key, values] of multi) {
		o[key] = values.length > 1 ? values : values[0];
	}
	return o;
}

function headerEntries(
	headers: Headers | Record<string, string | string[] | undefined> | Iterable<[string, string]>,
): Iterable<[string, string | string[] | undefined]> {
	if (headers instanceof Headers) {
		const list: [string, string][] = [];
		headers.forEach((value, key) => list.push([key, value]));
		const setCookie = headers.getSetCookie();
		if (setCookie.length <= 1) {
			return list;
		}
		// Headers joins duplicate set-cookie values; restore them as individual values (after the other headers)
		return [...list.filter(([k]) => k !== "set-cookie"), ...setCookie.map((c): [string, string] => ["set-cookie", c])];
	}
	return Symbol.iterator in headers ? (headers as Iterable<[string, string]>) : Object.entries(headers);
}

function stackOf(e: Error): string[] {
	return (e.stack ?? "")
		.split("\n")
		.slice(1)
		.map((l) => l.trim());
}

/**
 * Create log args describing an exception. Port of DataUtils.ex().
 */
export function ex(exception: unknown, input: LogArgs = {}): LogArgs {
	if (exception == null) {
		return input;
	}
	const e = exception instanceof Error ? exception : new Error(String(exception));
	const event: LogArgs = { ...input };
	event["error"] = e.message;
	event["error_class"] = e.name;
	const cause = e.cause;
	if (cause instanceof Error) {
		event["cause"] = cause.message;
		event["cause_class"] = cause.name;
		event["cause_stacktrace"] = stackOf(cause);
	} else if (cause !== undefined) {
		event["cause"] = String(cause);
	}
	event["result"] = ConditionResult.FAILURE;
	if (!("msg" in input)) {
		event["msg"] = "unexpected exception caught: " + e.message;
		event["stacktrace"] = stackOf(e);
	}
	return event;
}

/**
 * Convert a JSON object of headers (values may be strings or arrays of strings) to a Headers object
 */
export function headersFromJson(headerJson: JsonObject | null | undefined, headers: Headers = new Headers()): Headers {
	if (headerJson != null) {
		for (const [header, v] of Object.entries(headerJson)) {
			if (Array.isArray(v)) {
				headers.delete(header);
				for (const x of v) {
					headers.append(header, String(x));
				}
			} else {
				headers.set(header, String(v));
			}
		}
	}
	return headers;
}
