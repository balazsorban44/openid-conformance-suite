/**
 * JSON types and strict accessors.
 *
 * Upstream (Java) uses Gson's JsonElement/JsonObject/JsonArray and a set of strict wrappers in
 * `testmodule/OIDFJSON.java` that never coerce types. This file is the TypeScript equivalent:
 * plain JSON values plus the same strict accessors.
 *
 * Mapping from Gson:
 *   JsonObject            -> JsonObject (plain object)
 *   JsonArray             -> JsonArray (plain array)
 *   JsonElement           -> JsonValue
 *   JsonNull              -> null
 *   obj.get("x") == null  -> obj["x"] == null  (missing *or* JSON null; see notes in the porting skill)
 *   obj.has("x")          -> has(obj, "x")
 *   el.isJsonObject()     -> isJsonObject(el)
 *   el.isJsonArray()      -> isJsonArray(el)
 *   el.isJsonPrimitive() && el.getAsJsonPrimitive().isString() -> typeof el === "string"
 *   el.deepCopy()         -> deepCopy(el)
 *   el.toString()         -> JSON.stringify(el)
 *   JsonParser.parseString(s) -> parseJson(s)  (throws JsonParseException)
 */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;
export type JsonArray = JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export class JsonParseException extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "JsonParseException";
	}
}

export class UnexpectedJsonTypeException extends Error {
	constructor(message: string) {
		super(message);
		this.name = "UnexpectedJsonTypeException";
	}
}

/** Thrown if the value is JsonNull (port of OIDFJSON.ValueIsJsonNullException) */
export class ValueIsJsonNullException extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ValueIsJsonNullException";
	}
}

export function isJsonObject(v: unknown): v is JsonObject {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function isJsonArray(v: unknown): v is JsonArray {
	return Array.isArray(v);
}

/** Gson's el.isJsonPrimitive() */
export function isJsonPrimitive(v: unknown): v is string | number | boolean {
	return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

/** Gson's el.isJsonNull(): the element is present and is JSON null */
export function isJsonNull(v: unknown): v is null {
	return v === null;
}

/** Gson's obj.has(key) */
export function has(obj: JsonObject | null | undefined, key: string): boolean {
	return obj != null && Object.prototype.hasOwnProperty.call(obj, key);
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

/** Gson's el.deepCopy() */
export function deepCopy<T extends JsonValue | undefined>(v: T): T {
	if (v === undefined || v === null) {
		return v;
	}
	return structuredClone(v);
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
		const kb = Object.keys(b);
		return ka.length === kb.length && ka.every((k) => has(b, k) && jsonEquals(a[k], b[k]));
	}
	return false;
}

/** Gson's JsonArray.contains(new JsonPrimitive(x)) */
export function jsonArrayContains(arr: JsonArray | null | undefined, value: JsonValue): boolean {
	return arr != null && arr.some((x) => jsonEquals(x, value));
}

/**
 * Wrappers around the GSON getAsXXXX methods (port of testmodule/OIDFJSON.java).
 *
 * The 'get' methods must NEVER do any type conversion; if type conversion is necessary call
 * the method 'forceConversionTo...'
 */
export const OIDFJSON = {
	getNumber(json: unknown): number {
		if (typeof json !== "number") {
			throw new UnexpectedJsonTypeException(
				"getNumber called on something that is not a number: " + JSON.stringify(json),
			);
		}
		return json;
	},
	getInt(json: unknown): number {
		if (typeof json !== "number") {
			throw new UnexpectedJsonTypeException("getInt called on something that is not a number: " + JSON.stringify(json));
		}
		return Math.trunc(json);
	},
	getLong(json: unknown): number {
		if (typeof json !== "number") {
			throw new UnexpectedJsonTypeException(
				"getLong called on something that is not a number: " + JSON.stringify(json),
			);
		}
		return Math.trunc(json);
	},
	getDouble(json: unknown): number {
		if (typeof json !== "number") {
			throw new UnexpectedJsonTypeException(
				"getDouble called on something that is not a number: " + JSON.stringify(json),
			);
		}
		return json;
	},
	getString(json: unknown): string {
		if (typeof json !== "string") {
			throw new UnexpectedJsonTypeException(
				"getString called on something that is not a string: " + JSON.stringify(json),
			);
		}
		return json;
	},
	getStringOrNull(json: unknown): string | null {
		if (json == null) {
			return null;
		}
		return OIDFJSON.getString(json);
	},
	/** True when the element is a non-null JSON string primitive — the precondition for getString. */
	isString(json: unknown): json is string {
		return typeof json === "string";
	},
	getBoolean(json: unknown): boolean {
		if (typeof json !== "boolean") {
			throw new UnexpectedJsonTypeException(
				"getBoolean called on something that is not a boolean: " + JSON.stringify(json),
			);
		}
		return json;
	},
	forceConversionToString(json: unknown): string {
		if (typeof json !== "string" && typeof json !== "number") {
			throw new UnexpectedJsonTypeException(
				"forceConversionToString called on something that is neither a number nor a string: " + JSON.stringify(json),
			);
		}
		return String(json);
	},
	/**
	 * Unlike getNumber, it will not throw an error if it's a json string containing a number
	 */
	forceConversionToNumber(json: unknown): number {
		if (json === null) {
			throw new ValueIsJsonNullException("Element has a JsonNull value");
		}
		if (typeof json === "number") {
			return json;
		}
		if (typeof json === "string") {
			const n = Number(json);
			if (json.trim() === "" || Number.isNaN(n)) {
				throw new UnexpectedJsonTypeException(
					"forceConversionToNumber called on a string that is not a number: " + json,
				);
			}
			return n;
		}
		throw new UnexpectedJsonTypeException(
			"forceConversionToNumber called on something that is neither a number nor a string: " + JSON.stringify(json),
		);
	},
	tryGetString(json: unknown): string | null {
		if (json == null) {
			return null;
		}
		return OIDFJSON.getString(json);
	},
	convertMapToJsonObject(map: Record<string, unknown>): JsonObject {
		return JSON.parse(JSON.stringify(map)) as JsonObject;
	},
};
