import { type JsonArray, type JsonObject, type JsonValue, isJsonObject, parseJsonObject } from "./json.ts";
import { NamedError } from "./NamedError.ts";

type PrimitiveTypes = { string: string; number: number; boolean: boolean };

/**
 * Port of testmodule/Environment.java
 *
 * An element for storing the current running state of a test module in a way that it can be passed around.
 *
 * The Environment stores JSON objects indexed by strings. Items in the JSON objects themselves can be indexed by
 * foo.bar.baz path selectors using the getString(key, path) and getElementFromObject(key, path) functions.
 *
 * Object keys can be mapped, such that one key shadows another stored object (see mapKey()).
 *
 * Native values (strings, integers, longs, booleans) can be stored and accessed through special accessor
 * functions. A native value and a JSON object can be stored using the same key, but the two of these are
 * unrelated to each other. Native value keys are never mapped.
 *
 * Differences from Java:
 *  - getters return `null` when the object/element is missing (as in Java); getElementFromObject returns
 *    `undefined` when missing and `null` for a present JSON null.
 *  - there is no lock; see AbstractTestModule for the (single-threaded) status machine.
 */
export class Environment {
	// key for storing native values directly
	private static readonly NATIVE_VALUES = "_NATIVE_VALUES";

	private store = new Map<string, JsonObject>([[Environment.NATIVE_VALUES, {}]]);
	private keyMap = new Map<string, string>();
	private systemCounters = new Map<string, number>();

	/**
	 * Returns the next value of the named per-instance counter, starting at 0 on first call.
	 */
	nextSystemCounter(key: string): number {
		const v = this.systemCounters.get(key) ?? 0;
		this.systemCounters.set(key, v + 1);
		return v;
	}

	/** Check to see if there is an object in the Environment referenced by the given key (mapped keys dereferenced) */
	containsObject(key: string): boolean {
		return this.store.has(this.getEffectiveKey(key));
	}

	/** Get a JSON object from the Environment store, or null if it does not exist */
	getObject(key: string): JsonObject | null {
		return this.store.get(this.getEffectiveKey(key)) ?? null;
	}

	/** Remove a JSON object from this environment, if it exists */
	removeObject(key: string): void {
		this.store.delete(this.getEffectiveKey(key));
	}

	/**
	 * Put an object into the Environment, overwriting an existing object if one is there.
	 * Passing null removes the object.
	 */
	putObject(key: string, value: JsonObject | null): JsonObject | null;
	putObject(key: string, path: string, value: JsonObject): void;
	putObject(key: string, pathOrValue: string | JsonObject | null, value?: JsonObject): JsonObject | null | undefined {
		if (typeof pathOrValue === "string") {
			this.putElement(key, pathOrValue, value as JsonObject);
			return undefined;
		}
		const effectiveKey = this.getEffectiveKey(key);
		const previous = this.store.get(effectiveKey) ?? null;
		if (pathOrValue == null) {
			this.store.delete(effectiveKey);
		} else {
			this.store.set(effectiveKey, pathOrValue);
		}
		return previous;
	}

	private putElement(key: string, path: string, value: JsonValue): void {
		let o = this.getObject(key);
		if (o == null) {
			o = {};
			this.putObject(key, o);
		}
		const [parent, lastSegment] = walkToParent(o, key, path, (missingIn, segment) => (missingIn[segment] = {}));
		parent[lastSegment] = value;
	}

	putArray(key: string, path: string, value: JsonArray): void {
		this.putElement(key, path, value);
	}

	/** Remove an element at the given dot-separated path within an object */
	removeElement(key: string, path: string): void {
		const notFound = () => new NoSuchElementException(`No object with key ${key} found in path ${path}`);
		const o = this.getObject(key);
		if (o == null) {
			throw notFound();
		}
		const [parent, lastSegment] = walkToParent(o, key, path, () => {
			throw notFound();
		});
		delete parent[lastSegment];
	}

	putObjectFromJsonString(key: string, json: string): JsonObject | null;
	putObjectFromJsonString(key: string, path: string, json: string): void;
	putObjectFromJsonString(key: string, pathOrJson: string, json?: string): JsonObject | null | undefined {
		if (json === undefined) {
			return this.putObject(key, parseJsonObject(pathOrJson));
		}
		this.putObject(key, pathOrJson, parseJsonObject(json));
		return undefined;
	}

	/**
	 * Get a sub-element from a JSON object within the environment, if that object exists.
	 *
	 * The path elements are separated by ".". Returns undefined if the object identified by the key
	 * is not found, or the object does not contain any element at the path. A present JSON null is returned as null.
	 */
	getElementFromObject(key: string, path: string): JsonValue | undefined {
		let e: JsonValue | null = this.getObject(key);
		if (e == null) {
			return undefined;
		}
		for (const p of path.split(".")) {
			if (!isJsonObject(e)) {
				throw new UnexpectedTypeException(
					`An object is required for ${key}.${path} but ${typeName(e)} was found whilst traversing the path`,
				);
			}
			if (!Object.hasOwn(e, p)) {
				return undefined;
			}
			e = e[p];
		}
		return e;
	}

	/**
	 * Gets a sub-element from a named object at the given path and returns it as a native string, if it is stored as one.
	 * With a single argument, reads from the native value store.
	 */
	getString(key: string, path?: string): string | null {
		return this.getPrimitive(key, path, "string", "If present, a string is expected");
	}

	getInteger(key: string, path?: string): number | null {
		const n = this.getPrimitive(key, path, "number", "A number is required");
		return n == null ? null : Math.trunc(n);
	}

	getBoolean(key: string, path?: string): boolean | null {
		return this.getPrimitive(key, path, "boolean", "A boolean is required");
	}

	/** Java's getLong: the same as getInteger (JavaScript has one number type) */
	getLong(key: string, path?: string): number | null {
		return this.getInteger(key, path);
	}

	/**
	 * The element at key/path (the native value `key` when there is no path) if it has the given type; null when
	 * missing or JSON null; UnexpectedTypeException("<expectation> for <key> <path> but <type> was found") otherwise.
	 */
	private getPrimitive<T extends keyof PrimitiveTypes>(
		key: string,
		path: string | undefined,
		type: T,
		expectation: string,
	): PrimitiveTypes[T] | null {
		if (path === undefined) {
			return this.getPrimitive(Environment.NATIVE_VALUES, key, type, expectation);
		}
		const e = this.getElementFromObject(key, path);
		if (e == null) {
			return null;
		}
		if (typeof e === type) {
			return e as PrimitiveTypes[T];
		}
		throw new UnexpectedTypeException(`${expectation} for ${key} ${path} but ${typeName(e)} was found`);
	}

	toString(): string {
		return (
			'Environment: { "store" : ' +
			JSON.stringify(Object.fromEntries(this.store)) +
			', "keyMap" : ' +
			JSON.stringify(Object.fromEntries(this.keyMap)) +
			" }"
		);
	}

	/** Serializable snapshot (used for the final environment dump in the test log) */
	toJSON(): { store: Record<string, JsonObject>; keyMap: Record<string, string> } {
		return { store: Object.fromEntries(this.store), keyMap: Object.fromEntries(this.keyMap) };
	}

	/** If the key is mapped to another value, get the underlying value. Otherwise return the input key itself. */
	getEffectiveKey(key: string): string {
		return this.keyMap.get(key) ?? key;
	}

	/**
	 * Add a mapping from one key value to another. When things are looked up by "from" it will look for "to" in the
	 * storage instead. This lookup does not chain to multiple levels.
	 * @returns the previously mapped "to" or null if not mapped
	 */
	mapKey(from: string, to: string): string | null {
		const prev = this.keyMap.get(from) ?? null;
		this.keyMap.set(from, to);
		return prev;
	}

	/** Remove a mapped key. @returns the previously mapped key or null */
	unmapKey(key: string): string | null {
		const prev = this.keyMap.get(key) ?? null;
		this.keyMap.delete(key);
		return prev;
	}

	/** Test if a key has had another key mapped over it (key is a "to" value in mapKey) */
	isKeyShadowed(key: string): boolean {
		return [...this.keyMap.values()].includes(key);
	}

	/** Test if a given key is mapped to another value (key is a "from" value in mapKey) */
	isKeyMapped(key: string): boolean {
		return this.keyMap.has(key);
	}

	//
	// Native value accessor functions
	//

	putLong(key: string, value: number | null): void;
	putLong(key: string, path: string, value: number): void;
	putLong(key: string, pathOrValue: string | number | null, value?: number): void {
		if (typeof pathOrValue === "string") {
			this.putElement(key, pathOrValue, value as number);
			return;
		}
		this.natives()[key] = pathOrValue;
	}

	putInteger(key: string, value: number | null): void {
		this.natives()[key] = value;
	}

	putBoolean(key: string, value: boolean | null): void {
		this.natives()[key] = value;
	}

	putString(key: string, value: string | null): void;
	putString(key: string, path: string, value: string | null): void;
	putString(key: string, pathOrValue: string | null, value?: string | null): void {
		if (value !== undefined) {
			this.putElement(key, pathOrValue as string, value);
			return;
		}
		this.natives()[key] = pathOrValue;
	}

	/** Remove a value from the native objects store, if it exists. */
	removeNativeValue(key: string): void {
		delete this.natives()[key];
	}

	private natives(): JsonObject {
		return this.store.get(Environment.NATIVE_VALUES) as JsonObject;
	}
}

/**
 * Follows the dot-separated path to the object holding its last segment; returns that object and the segment.
 * `onMissing` handles an absent intermediate object (returning the object to continue with, or throwing).
 */
function walkToParent(
	o: JsonObject,
	key: string,
	path: string,
	onMissing: (o: JsonObject, segment: string) => JsonObject,
): [JsonObject, string] {
	const pathSegments = path.split(".");
	const lastSegment = pathSegments.pop() as string;
	for (const pathSegment of pathSegments) {
		const next = o[pathSegment];
		if (next === undefined) {
			o = onMissing(o, pathSegment);
		} else if (isJsonObject(next)) {
			o = next;
		} else {
			throw new UnexpectedTypeException(
				`putObject(${key}, ${path}, obj) found a non-object of type ${typeName(next)} in the path at ${pathSegment}`,
			);
		}
	}
	return [o, lastSegment];
}

function typeName(v: JsonValue | undefined): string {
	if (v === null) {
		return "JsonNull";
	}
	if (v === undefined) {
		return "undefined";
	}
	if (Array.isArray(v)) {
		return "JsonArray";
	}
	if (typeof v === "object") {
		return "JsonObject";
	}
	return "JsonPrimitive";
}

/**
 * To allow conditions catch these exceptions when necessary
 * i.e to catch and throw a nicer 'error(..., args(...))' from a condition
 */
export class UnexpectedTypeException extends NamedError {}

export class NoSuchElementException extends NamedError {}
