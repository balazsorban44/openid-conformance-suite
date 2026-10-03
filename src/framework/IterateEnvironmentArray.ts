import type { TestExecutionUnit } from "./ConditionCallBuilder.ts";
import {
	ConditionSequenceCallBuilder,
	type ConditionSequenceClass,
	type ConditionSequenceSupplier,
} from "./ConditionSequence.ts";
import type { Environment } from "./Environment.ts";
import { deepCopy, isJsonObject, OIDFJSON, type JsonObject, type JsonValue } from "./json.ts";

export interface IterationContext {
	element: JsonValue;
	iteration: number;
	iterationCount: number;
}

/**
 * Port of testmodule/IterateEnvironmentArray.java
 *
 * A test execution unit that iterates over an environment array and runs a sub-sequence once per element.
 */
export class IterateEnvironmentArray implements TestExecutionUnit {
	readonly unitKind = "iterate";
	private readonly sourceObject: string;
	private readonly sourcePath: string;
	private readonly sequenceCallBuilder: ConditionSequenceCallBuilder;

	private currentElementObject: string | null = null;
	private currentElementPath: string | null = null;
	private currentStringKey: string | null = null;
	private iterationIndexKey: string | null = null;
	private iterationCountKey: string | null = null;
	private logBlockLabelBuilder: ((ctx: IterationContext) => string) | null = null;

	constructor(sourceObject: string, sourcePath: string, sequence: ConditionSequenceClass | ConditionSequenceSupplier) {
		this.sourceObject = sourceObject;
		this.sourcePath = sourcePath;
		this.sequenceCallBuilder = new ConditionSequenceCallBuilder(sequence);
	}

	currentElement(envObjectKey: string, envPath: string): this {
		this.currentElementObject = envObjectKey;
		this.currentElementPath = envPath;
		return this;
	}

	currentString(envStringKey: string): this {
		this.currentStringKey = envStringKey;
		return this;
	}

	iterationIndex(envIntegerKey: string): this {
		this.iterationIndexKey = envIntegerKey;
		return this;
	}

	iterationCount(envIntegerKey: string): this {
		this.iterationCountKey = envIntegerKey;
		return this;
	}

	logBlockLabels(builder: (ctx: IterationContext) => string): this {
		this.logBlockLabelBuilder = builder;
		return this;
	}

	getSourceObject(): string {
		return this.sourceObject;
	}

	getSourcePath(): string {
		return this.sourcePath;
	}

	getSequenceCallBuilder(): ConditionSequenceCallBuilder {
		return this.sequenceCallBuilder;
	}

	prepareIteration(env: Environment, element: JsonValue, iterationIndex: number, iterationCount: number): void {
		if (this.currentElementObject && this.currentElementPath) {
			putElement(env, this.currentElementObject, this.currentElementPath, deepCopy(element));
		}
		if (this.currentStringKey) {
			if (typeof element !== "string") {
				throw new Error("Current iteration element is not a string");
			}
			env.putString(this.currentStringKey, OIDFJSON.getString(element));
		}
		if (this.iterationIndexKey) {
			env.putInteger(this.iterationIndexKey, iterationIndex + 1);
		}
		if (this.iterationCountKey) {
			env.putInteger(this.iterationCountKey, iterationCount);
		}
	}

	getLogBlockLabel(element: JsonValue, iterationIndex: number, iterationCount: number): string | null {
		if (this.logBlockLabelBuilder == null) {
			return null;
		}
		return this.logBlockLabelBuilder({ element: deepCopy(element), iteration: iterationIndex + 1, iterationCount });
	}

	cleanupAfterIteration(env: Environment, iterationCount: number): void {
		if (iterationCount === 0) {
			return;
		}
		if (this.currentElementObject && this.currentElementPath) {
			env.removeElement(this.currentElementObject, this.currentElementPath);
		}
		if (this.currentStringKey) {
			env.removeNativeValue(this.currentStringKey);
		}
		if (this.iterationIndexKey) {
			env.removeNativeValue(this.iterationIndexKey);
		}
		if (this.iterationCountKey) {
			env.removeNativeValue(this.iterationCountKey);
		}
	}
}

function putElement(env: Environment, key: string, path: string, value: JsonValue): void {
	let o: JsonObject = env.getObject(key) ?? {};
	if (!env.containsObject(key)) {
		env.putObject(key, o);
	}
	const pathSegments = path.split(".");
	const lastSegment = pathSegments.pop() as string;
	for (const pathSegment of pathSegments) {
		let next: JsonValue | undefined = o[pathSegment];
		if (next === undefined) {
			next = {};
			o[pathSegment] = next;
		} else if (!isJsonObject(next)) {
			throw new Error("Non-object value found while writing iteration element to " + key + "." + path);
		}
		o = next;
	}
	o[lastSegment] = value;
}
