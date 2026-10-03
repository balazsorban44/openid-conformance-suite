import type { ConditionClass } from "./Condition.ts";
import type { TestExecutionUnit } from "./ConditionCallBuilder.ts";

/** Port of sequence/ConditionSequence.java */
export interface ConditionSequence extends TestExecutionUnit {
	readonly unitKind: "sequence";
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
}

/** Port of testmodule/ConditionSequenceCallBuilder.java */
export class ConditionSequenceCallBuilder implements TestExecutionUnit {
	readonly unitKind = "sequence-call";
	/** Instantiate the sequence this builder describes (a new instance on every call) */
	readonly create: ConditionSequenceSupplier;

	constructor(classOrSupplier: ConditionSequenceClass | ConditionSequenceSupplier) {
		// Java takes a Class or a Supplier; here both are functions. A class is constructed; an arrow function
		// supplier (no prototype, not constructible) is called.
		this.create =
			"prototype" in classOrSupplier
				? () => new (classOrSupplier as ConditionSequenceClass)()
				: (classOrSupplier as ConditionSequenceSupplier);
	}
}
