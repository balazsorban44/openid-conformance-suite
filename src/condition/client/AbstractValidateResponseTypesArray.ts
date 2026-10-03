import { AbstractValidateJsonArray } from "./AbstractValidateJsonArray.ts";

export abstract class AbstractValidateResponseTypesArray extends AbstractValidateJsonArray {
	protected override elementsEqual(e1: string, e2: string): boolean {
		// UPSTREAM: Java Set.of(...) throws IllegalArgumentException on duplicate elements (e.g. "code code"); not replicated
		const s1 = new Set(e1.split(" "));
		const s2 = new Set(e2.split(" "));
		return s1.size === s2.size && [...s1].every((v) => s2.has(v));
	}
}
