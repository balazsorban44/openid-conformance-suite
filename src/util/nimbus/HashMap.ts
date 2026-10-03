/**
 * The iteration order of a `java.util.HashMap` (JDK 21), which decides the JSON member order of everything Nimbus
 * serializes (headers, claims sets, JWKs, JWK sets go through HashMaps before Gson writes them).
 *
 * Not lock-tracked: there is no upstream Java file for this module.
 */
import type { JsonObject, JsonValue } from "../../framework/json.ts";

/**
 * Emulates the iteration order of a `java.util.HashMap` (JDK 21): Nimbus serializes headers, claims, JWKs and JWK
 * sets through HashMaps, so the Java JSON objects have their members in hash order, not in insertion order.
 * Integer-like member names still come first in a JS object, whatever is done here.
 */
export class JavaHashMap {
	private table: string[][] | null = null;
	private threshold = 0;
	private readonly values = new Map<string, JsonValue>();

	static of(entries: Iterable<[string, JsonValue]>): JavaHashMap {
		const m = new JavaHashMap();
		for (const [k, v] of entries) {
			m.put(k, v);
		}
		return m;
	}

	/** java.lang.String.hashCode() spread as in HashMap.hash() */
	private static hash(key: string): number {
		let h = 0;
		for (let i = 0; i < key.length; i++) {
			h = (Math.imul(31, h) + key.charCodeAt(i)) | 0;
		}
		return h ^ (h >>> 16);
	}

	private static tableSizeFor(c: number): number {
		let n = 1;
		while (n < c) {
			n *= 2;
		}
		return n;
	}

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
				newTable[JavaHashMap.hash(key) & (newCap - 1)].push(key);
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
		table[JavaHashMap.hash(key) & (table.length - 1)].push(key);
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
					this.threshold = JavaHashMap.tableSizeFor(t);
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
