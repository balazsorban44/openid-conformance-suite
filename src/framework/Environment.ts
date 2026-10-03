import { type JsonArray, type JsonObject, type JsonValue, isJsonObject, parseJsonObject, OIDFJSON } from "./json.ts";

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
		let o: JsonObject = this.getObject(key) ?? {};
		if (!this.containsObject(key)) {
			this.putObject(key, o);
		}
		const pathSegments = path.split(".");
		const lastSegment = pathSegments.pop() as string;
		for (const pathSegment of pathSegments) {
			let nextO: JsonValue | undefined = o[pathSegment];
			if (nextO === undefined) {
				nextO = {};
				o[pathSegment] = nextO;
			} else if (!isJsonObject(nextO)) {
				throw new UnexpectedTypeException(
					`putObject(${key}, ${path}, obj) found a non-object of type ${typeName(nextO)} in the path at ${pathSegment}`,
				);
			}
			o = nextO;
		}
		o[lastSegment] = value;
	}

	putArray(key: string, path: string, value: JsonArray): void {
		this.putElement(key, path, value);
	}

	/** Remove an element at the given dot-separated path within an object */
	removeElement(key: string, path: string): void {
		let o: JsonObject | null = this.getObject(key);
		if (o == null) {
			throw new NoSuchElementException(`No object with key ${key} found in path ${path}`);
		}
		const pathSegments = path.split(".");
		const lastSegment = pathSegments.pop() as string;
		for (const pathSegment of pathSegments) {
			const nextO: JsonValue | undefined = o[pathSegment];
			if (nextO === undefined) {
				throw new NoSuchElementException(`No object with key ${key} found in path ${path}`);
			} else if (!isJsonObject(nextO)) {
				throw new UnexpectedTypeException(
					`putObject(${key}, ${path}, obj) found a non-object of type ${typeName(nextO)} in the path at ${pathSegment}`,
				);
			}
			o = nextO;
		}
		delete o[lastSegment];
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
		let e: JsonValue | undefined = this.getObject(key) ?? undefined;
		if (e === undefined) {
			return undefined;
		}
		const parts = path.split(".");
		for (let i = 0; i < parts.length; i++) {
			const p = parts[i];
			if (isJsonObject(e)) {
				if (Object.prototype.hasOwnProperty.call(e, p)) {
					e = e[p];
					if (i === parts.length - 1) {
						return e;
					}
				} else {
					break;
				}
			} else {
				throw new UnexpectedTypeException(
					`An object is required for ${key}.${path} but ${typeName(e)} was found whilst traversing the path`,
				);
			}
		}
		return undefined;
	}

	/**
	 * Gets a sub-element from a named object at the given path and returns it as a native string, if it is stored as one.
	 * With a single argument, reads from the native value store.
	 */
	getString(key: string, path?: string): string | null {
		if (path === undefined) {
			return this.getString(Environment.NATIVE_VALUES, key);
		}
		const e = this.getElementFromObject(key, path);
		if (e == null) {
			return null;
		}
		if (typeof e === "string") {
			return e;
		}
		throw new UnexpectedTypeException(
			`If present, a string is expected for ${key} ${path} but ${typeName(e)} was found`,
		);
	}

	getInteger(key: string, path?: string): number | null {
		if (path === undefined) {
			return this.getInteger(Environment.NATIVE_VALUES, key);
		}
		const e = this.getElementFromObject(key, path);
		if (e == null) {
			return null;
		}
		if (typeof e === "number") {
			return Math.trunc(e);
		}
		throw new UnexpectedTypeException(`A number is required for ${key} ${path} but ${typeName(e)} was found`);
	}

	getBoolean(key: string, path?: string): boolean | null {
		if (path === undefined) {
			return this.getBoolean(Environment.NATIVE_VALUES, key);
		}
		const e = this.getElementFromObject(key, path);
		if (e == null) {
			return null;
		}
		if (typeof e === "boolean") {
			return e;
		}
		throw new UnexpectedTypeException(`A boolean is required for ${key} ${path} but ${typeName(e)} was found`);
	}

	getLong(key: string, path?: string): number | null {
		if (path === undefined) {
			return this.getLong(Environment.NATIVE_VALUES, key);
		}
		const e = this.getElementFromObject(key, path);
		if (e == null) {
			return null;
		}
		if (typeof e === "number") {
			return Math.trunc(e);
		}
		throw new UnexpectedTypeException(`A number is required for ${key} ${path} but ${typeName(e)} was found`);
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
		for (const v of this.keyMap.values()) {
			if (v === key) {
				return true;
			}
		}
		return false;
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

	/** Executes the given code block with the supplied key mapping and resets the mapping after completion. */
	async runWithMapKey(from: string, to: string, code: () => void | Promise<void>): Promise<void> {
		this.mapKey(from, to);
		try {
			await code();
		} finally {
			this.unmapKey(from);
		}
	}

	private natives(): JsonObject {
		return this.store.get(Environment.NATIVE_VALUES) as JsonObject;
	}

	/** Helper for ported code: equivalent of OIDFJSON.getString(env.getElementFromObject(key, path)) */
	getStringStrict(key: string, path: string): string {
		return OIDFJSON.getString(this.getElementFromObject(key, path));
	}
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
export class UnexpectedTypeException extends Error {
	constructor(msg: string) {
		super(msg);
		this.name = "UnexpectedTypeException";
	}
}

export class NoSuchElementException extends Error {
	constructor(msg: string) {
		super(msg);
		this.name = "NoSuchElementException";
	}
}
