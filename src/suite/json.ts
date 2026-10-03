/**
 * JSON as upstream handles it, for the Nimbus and JSON schema emulation: plain JSON for Gson's JsonElement /
 * JsonObject / JsonArray with the strict accessors of upstream's OIDFJSON (never a type conversion), Nimbus'
 * JSONObjectUtils (strict parsing, typed member getters, its error messages), and the iteration order of a
 * java.util.HashMap, which decides the member order of everything Nimbus serializes.
 */
import { NamedError, ParseException } from "./errors.ts";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;
export type JsonArray = JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export class JsonParseException extends NamedError {}

export class UnexpectedJsonTypeException extends NamedError {}

export function isJsonObject(v: unknown): v is JsonObject {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function isJsonArray(v: unknown): v is JsonArray {
	return Array.isArray(v);
}

/** Gson's JsonParser.parseString() */
export function parseJson(text: string): JsonValue {
	try {
		return JSON.parse(text) as JsonValue;
	} catch (e) {
		throw new JsonParseException((e as Error).message, { cause: e });
	}
}

/** Gson's JsonParser.parseString(s).getAsJsonObject() */
export function parseJsonObject(text: string): JsonObject {
	const v = parseJson(text);
	if (!isJsonObject(v)) {
		throw new UnexpectedJsonTypeException("Not a JSON Object: " + text);
	}
	return v;
}

/** Structural equality of two JSON values (Gson's JsonElement.equals) */
export function jsonEquals(a: JsonValue | undefined, b: JsonValue | undefined): boolean {
	if (a === b) {
		return true;
	}
	if (isJsonArray(a) && isJsonArray(b)) {
		return a.length === b.length && a.every((x, i) => jsonEquals(x, b[i]));
	}
	if (isJsonObject(a) && isJsonObject(b)) {
		const ka = Object.keys(a);
		return ka.length === Object.keys(b).length && ka.every((k) => Object.hasOwn(b, k) && jsonEquals(a[k], b[k]));
	}
	return false;
}

/** OIDFJSON.getString: the value if it is a string, else UnexpectedJsonTypeException (never a conversion) */
export function getString(json: unknown): string {
	if (typeof json !== "string") {
		throw new UnexpectedJsonTypeException(
			`getString called on something that is not a string: ${JSON.stringify(json)}`,
		);
	}
	return json;
}

/**
 * Nimbus `com.nimbusds.jose.util.JSONObjectUtils`: strict JSON object parsing (Gson underneath) and the typed
 * member getters every Nimbus `parse(Map)` method uses, with Nimbus' error messages.
 *
 * Nimbus JSONObjectUtils.getGeneric: null when missing or JSON null; throws on a wrong type. */
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

/** A {@link JavaHashMap} with the given entries, put in order */
export function javaHashMapOf(entries: Iterable<[string, JsonValue]>): JavaHashMap {
	const m = new JavaHashMap();
	for (const [k, v] of entries) {
		m.put(k, v);
	}
	return m;
}

/** java.lang.String.hashCode() spread as in HashMap.hash() */
function hash(key: string): number {
	let h = 0;
	for (let i = 0; i < key.length; i++) {
		h = (Math.imul(31, h) + key.charCodeAt(i)) | 0;
	}
	return h ^ (h >>> 16);
}

function tableSizeFor(c: number): number {
	let n = 1;
	while (n < c) {
		n *= 2;
	}
	return n;
}

/**
 * Emulates the iteration order of a `java.util.HashMap` (JDK 21): Nimbus serializes headers, claims, JWKs and JWK
 * sets through HashMaps, so the Java JSON objects have their members in hash order, not in insertion order.
 * Integer-like member names still come first in a JS object, whatever is done here.
 */
export class JavaHashMap {
	private table: string[][] | null = null;
	private threshold = 0;
	private readonly values = new Map<string, JsonValue>();

	private resize(): void {
		const oldCap = this.table?.length ?? 0;
		const oldThr = this.threshold;
		let newCap: number;
		let newThr: number;
		if (oldCap > 0) {
			newCap = oldCap * 2;
			newThr = oldCap >= 16 ? oldThr * 2 : Math.floor(newCap * 0.75);
		} else if (oldThr > 0) {
			newCap = oldThr;
			newThr = Math.floor(newCap * 0.75);
		} else {
			newCap = 16;
			newThr = 12;
		}
		const newTable: string[][] = Array.from({ length: newCap }, () => []);
		for (const bucket of this.table ?? []) {
			for (const key of bucket) {
				newTable[hash(key) & (newCap - 1)].push(key);
			}
		}
		this.table = newTable;
		this.threshold = newThr;
	}

	put(key: string, value: JsonValue): void {
		if (this.values.has(key)) {
			this.values.set(key, value);
			return;
		}
		if (this.table == null) {
			this.resize();
		}
		const table = this.table as string[][];
		table[hash(key) & (table.length - 1)].push(key);
		this.values.set(key, value);
		if (this.values.size > this.threshold) {
			this.resize();
		}
	}

	putAll(entries: [string, JsonValue][]): void {
		const s = entries.length;
		if (s > 0) {
			if (this.table == null) {
				// pre-size
				const t = Math.ceil(s / 0.75);
				if (t > this.threshold) {
					this.threshold = tableSizeFor(t);
				}
			} else {
				while (s > this.threshold) {
					this.resize();
				}
			}
			for (const [k, v] of entries) {
				this.put(k, v);
			}
		}
	}

	entries(): [string, JsonValue][] {
		const out: [string, JsonValue][] = [];
		for (const bucket of this.table ?? []) {
			for (const key of bucket) {
				out.push([key, this.values.get(key) as JsonValue]);
			}
		}
		return out;
	}

	toJsonObject(): JsonObject {
		const o: JsonObject = {};
		for (const [k, v] of this.entries()) {
			o[k] = v;
		}
		return o;
	}
}
