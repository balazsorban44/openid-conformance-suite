/**
 * Nimbus `com.nimbusds.jose.util.JSONObjectUtils`: strict JSON object parsing (Gson underneath) and the typed
 * member getters every Nimbus `parse(Map)` method uses, with Nimbus' error messages.
 *
 * Not lock-tracked: there is no upstream Java file for this module.
 */
import { isJsonArray, isJsonObject, type JsonArray, type JsonObject, type JsonValue } from "../../framework/json.ts";
import { ParseException } from "./errors.ts";

/** Nimbus JSONObjectUtils.getGeneric: null when missing or JSON null; throws on a wrong type. */
function nimbusGet<T>(o: JsonObject, name: string, check: (v: JsonValue) => v is T & JsonValue): T | null {
	const value = o[name];
	if (value == null) {
		return null;
	}
	if (!check(value)) {
		throw new ParseException("Unexpected type of JSON object member " + name + "");
	}
	return value;
}

const isStr = (v: JsonValue): v is string => typeof v === "string";
const isNum = (v: JsonValue): v is number => typeof v === "number";
const isBool = (v: JsonValue): v is boolean => typeof v === "boolean";
const isArr = (v: JsonValue): v is JsonArray => Array.isArray(v);
const isObj = (v: JsonValue): v is JsonObject => isJsonObject(v);

/** Nimbus JSONObjectUtils.getString */
export function nimbusGetString(o: JsonObject, name: string): string | null {
	return nimbusGet(o, name, isStr);
}

/** Nimbus JSONObjectUtils.getJSONArray */
export function nimbusGetJSONArray(o: JsonObject, name: string): JsonArray | null {
	return nimbusGet(o, name, isArr);
}

/** Nimbus JSONObjectUtils.getJSONObject */
export function nimbusGetJSONObject(o: JsonObject, name: string): JsonObject | null {
	return nimbusGet(o, name, isObj);
}

/** Nimbus JSONObjectUtils.getBoolean (throws when missing) */
export function nimbusGetBoolean(o: JsonObject, name: string): boolean {
	const v = nimbusGet(o, name, isBool);
	if (v == null) {
		throw new ParseException("JSON object member " + name + " is missing or null");
	}
	return v;
}

/** Nimbus JSONObjectUtils.getLong / getInt (throws when missing; truncates like Number.longValue()) */
export function nimbusGetLong(o: JsonObject, name: string): number {
	const v = nimbusGet(o, name, isNum);
	if (v == null) {
		throw new ParseException("JSON object member " + name + " is missing or null");
	}
	return Math.trunc(v);
}

/** Nimbus JSONObjectUtils.getStringList */
export function nimbusGetStringList(o: JsonObject, name: string): (string | null)[] | null {
	const arr = nimbusGetJSONArray(o, name);
	if (arr == null) {
		return null;
	}
	for (const item of arr) {
		if (item !== null && typeof item !== "string") {
			throw new ParseException("JSON object member " + name + " is not an array of strings");
		}
	}
	return arr as (string | null)[];
}

/** Nimbus JSONObjectUtils.getURI (java.net.URI syntax check, approximated) */
export function nimbusGetURI(o: JsonObject, name: string): string | null {
	const value = nimbusGetString(o, name);
	if (value == null) {
		return null;
	}
	// java.net.URI rejects whitespace, control characters and a few ASCII punctuation characters
	// oxlint-disable-next-line no-control-regex
	const m = /[\s"<>\\^`{|}\u0000-\u001f\u007f]/.exec(value);
	if (m) {
		throw new ParseException(uriSyntaxMessage(value, m.index));
	}
	return value;
}

/** The java.net.URISyntaxException message for an illegal character (approximating which component it is in). */
function uriSyntaxMessage(value: string, index: number): string {
	const schemeEnd = value.indexOf(":");
	let component = "path";
	if (schemeEnd !== -1 && index < schemeEnd) {
		component = "scheme name";
	} else {
		const hashIndex = value.indexOf("#");
		const queryIndex = value.indexOf("?");
		if (hashIndex !== -1 && index > hashIndex) {
			component = "fragment";
		} else if (queryIndex !== -1 && index > queryIndex) {
			component = "query";
		} else if (schemeEnd !== -1 && value.startsWith("//", schemeEnd + 1)) {
			const authorityStart = schemeEnd + 3;
			const rest = value.substring(authorityStart).search(/[/?#]/);
			const authorityEnd = rest === -1 ? value.length : authorityStart + rest;
			if (index < authorityEnd) {
				component = "authority";
			}
		}
	}
	return "Illegal character in " + component + " at index " + index + ": " + value;
}

/**
 * Nimbus JSONObjectUtils.parse(String): strict JSON, the top level must be an object and duplicate member
 * names are rejected (Gson's map adapter throws on them). Any failure is "Invalid JSON object".
 */
export function nimbusParseJsonObject(s: string, sizeLimit = -1): JsonObject {
	if (s.trim().length === 0) {
		throw new ParseException("Invalid JSON object");
	}
	if (sizeLimit >= 0 && s.length > sizeLimit) {
		throw new ParseException("The parsed string is longer than the max accepted size of " + sizeLimit + " characters");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(s);
	} catch {
		throw new ParseException("Invalid JSON object");
	}
	if (parsed === null) {
		// Gson returns null for a JSON null; Nimbus then fails with a NullPointerException
		throw new TypeError('Cannot invoke "java.util.Map.get(Object)" because "o" is null');
	}
	if (isJsonArray(parsed)) {
		// Gson's map adapter also accepts the array-of-pairs form: [["k", v], ...]
		const map: JsonObject = {};
		for (const pair of parsed) {
			if (!isJsonArray(pair) || pair.length !== 2 || (typeof pair[0] !== "string" && typeof pair[0] !== "number")) {
				throw new ParseException("Invalid JSON object");
			}
			const key = String(pair[0]);
			if (key in map) {
				throw new ParseException("Invalid JSON object");
			}
			map[key] = pair[1];
		}
		return map;
	}
	if (!isJsonObject(parsed) || hasDuplicateKeys(s)) {
		throw new ParseException("Invalid JSON object");
	}
	return parsed;
}

/**
 * Scans already-valid JSON text for a repeated member name in the top-level object (Gson's map adapter rejects
 * those; nested objects are read by its ObjectTypeAdapter, where the last value wins, as with JSON.parse).
 */
function hasDuplicateKeys(text: string): boolean {
	let i = 0;
	let depth = 0;
	const skipWs = () => {
		while (i < text.length && " \t\n\r".includes(text[i])) {
			i++;
		}
	};
	const readString = (): string => {
		const start = i;
		i++; // opening quote
		while (text[i] !== '"') {
			if (text[i] === "\\") {
				i++;
			}
			i++;
		}
		i++; // closing quote
		return JSON.parse(text.slice(start, i)) as string;
	};
	const readValue = (): boolean => {
		skipWs();
		const c = text[i];
		if (c === "{") {
			i++;
			const topLevel = depth === 0;
			depth++;
			const seen = new Set<string>();
			skipWs();
			if (text[i] === "}") {
				i++;
				return false;
			}
			for (;;) {
				skipWs();
				const key = readString();
				if (topLevel && seen.has(key)) {
					return true;
				}
				seen.add(key);
				skipWs();
				i++; // ':'
				if (readValue()) {
					return true;
				}
				skipWs();
				if (text[i] === ",") {
					i++;
					continue;
				}
				i++; // '}'
				return false;
			}
		}
		if (c === "[") {
			i++;
			skipWs();
			if (text[i] === "]") {
				i++;
				return false;
			}
			for (;;) {
				if (readValue()) {
					return true;
				}
				skipWs();
				if (text[i] === ",") {
					i++;
					continue;
				}
				i++; // ']'
				return false;
			}
		}
		if (c === '"') {
			readString();
			return false;
		}
		while (i < text.length && !",]} \t\n\r".includes(text[i])) {
			i++;
		}
		return false;
	};
	return readValue();
}
