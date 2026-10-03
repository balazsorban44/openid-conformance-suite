import type { ConditionClass } from "./Condition.ts";
import type { TestExecutionUnit } from "./ConditionCallBuilder.ts";

/** Port of sequence/ConditionSequence.java */
export interface ConditionSequence extends TestExecutionUnit {
	evaluate(): void;
	getTestExecutionUnits(): TestExecutionUnit[];
	replace(conditionToReplace: ConditionClass, builder: TestExecutionUnit): ConditionSequence;
	skip(conditionToSkip: ConditionClass, message: string): ConditionSequence;
	insertBefore(conditionToInsertAt: ConditionClass, builder: TestExecutionUnit): ConditionSequence;
	insertAfter(conditionToInsertAfter: ConditionClass, builder: TestExecutionUnit): ConditionSequence;
	then(...builders: TestExecutionUnit[]): ConditionSequence;
	butFirst(...builders: TestExecutionUnit[]): ConditionSequence;
}

export type ConditionSequenceClass = new () => ConditionSequence;
export type ConditionSequenceSupplier = () => ConditionSequence;

/** Port of sequence/SkippedCondition.java */
export class SkippedCondition implements TestExecutionUnit {
	readonly unitKind = "skipped";
	readonly source: string;
	readonly message: string;

	constructor(source: string, message: string) {
		this.source = source;
		this.message = message;
	}

	getSource(): string {
		return this.source;
	}

	getMessage(): string {
		return this.message;
	}
}

/** Port of testmodule/ConditionSequenceCallBuilder.java */
export class ConditionSequenceCallBuilder implements TestExecutionUnit {
	readonly unitKind = "sequence-call";
	private readonly conditionSequenceClass: ConditionSequenceClass | null;
	private readonly conditionSequenceConstructor: ConditionSequenceSupplier | null;

	constructor(classOrSupplier: ConditionSequenceClass | ConditionSequenceSupplier) {
		if (isClass(classOrSupplier)) {
			this.conditionSequenceClass = classOrSupplier;
			this.conditionSequenceConstructor = null;
		} else {
			this.conditionSequenceClass = null;
			this.conditionSequenceConstructor = classOrSupplier;
		}
	}

	getConditionSequenceClass(): ConditionSequenceClass | null {
		return this.conditionSequenceClass;
	}

	getConditionSequenceConstructor(): ConditionSequenceSupplier | null {
		return this.conditionSequenceConstructor;
	}

	/** Instantiate the sequence this builder describes */
	create(): ConditionSequence {
		if (this.conditionSequenceConstructor) {
			return this.conditionSequenceConstructor();
		}
		return new (this.conditionSequenceClass as ConditionSequenceClass)();
	}
}

/**
 * Distinguish `class Foo {}` from `() => new Foo()`: classes have a prototype object with a constructor,
 * arrow functions do not have a prototype property at all.
 */
export function isClass(v: unknown): v is new () => unknown {
	return (
		typeof v === "function" && typeof (v as { prototype?: unknown }).prototype === "object" && v.prototype !== null
	);
}
