import { ConditionResult, isConditionResult, type Condition, type ConditionClass } from "./Condition.ts";
import { ConditionCallBuilder, type TestExecutionUnit } from "./ConditionCallBuilder.ts";
import { Command } from "./Command.ts";
import {
	ConditionSequenceCallBuilder,
	SkippedCondition,
	type ConditionSequence,
	type ConditionSequenceClass,
	type ConditionSequenceSupplier,
} from "./ConditionSequence.ts";

/**
 * Port of sequence/AbstractConditionSequence.java
 *
 * A sequence records calls (it does not execute them); evaluate() is synchronous and only builds the list.
 * The test module executes the resulting units.
 */
export abstract class AbstractConditionSequence implements ConditionSequence {
	/** The condition class a unit calls, or null if it is not a condition call (Java: a protected static Function) */
	static actionToConditionClass(action: TestExecutionUnit): ConditionClass | null {
		return action.unitKind === "condition" ? (action as ConditionCallBuilder).conditionClass : null;
	}

	readonly unitKind = "sequence";
	private callables: TestExecutionUnit[] = [];
	private replacements = new Map<ConditionClass, TestExecutionUnit>();
	private skips = new Map<ConditionClass, string>();
	private _insertBefore = new Map<ConditionClass, TestExecutionUnit>();
	private _insertAfter = new Map<ConditionClass, TestExecutionUnit>();
	private before: TestExecutionUnit[] = [];
	private after: TestExecutionUnit[] = [];

	abstract evaluate(): void;

	/** Add the builder(s) to the list of calls to be made when this sequence is executed */
	protected call(builder: TestExecutionUnit | TestExecutionUnit[]): void {
		if (Array.isArray(builder)) {
			this.callables.push(...builder);
		} else {
			this.callables.push(builder);
		}
	}

	protected condition(condition: Condition | ConditionClass): ConditionCallBuilder {
		return new ConditionCallBuilder(condition);
	}

	protected exec(): Command {
		return new Command();
	}

	protected sequence(s: ConditionSequenceClass | ConditionSequenceSupplier): ConditionSequenceCallBuilder {
		return new ConditionSequenceCallBuilder(s);
	}

	protected sequenceOf(...units: TestExecutionUnit[]): ConditionSequence {
		return sequenceOf(...units);
	}

	private getCallablesWithSubSequencesExpanded(): TestExecutionUnit[] {
		const expandedUnits: TestExecutionUnit[] = [];
		for (const action of this.callables) {
			let sequence: ConditionSequence | null = null;
			if (action.unitKind === "sequence-call") {
				sequence = (action as ConditionSequenceCallBuilder).create();
			} else if (action.unitKind === "sequence") {
				sequence = action as ConditionSequence;
			}
			if (sequence != null) {
				sequence.evaluate();
				expandedUnits.push(...sequence.getTestExecutionUnits());
			} else {
				expandedUnits.push(action);
			}
		}
		return expandedUnits;
	}

	getTestExecutionUnits(): TestExecutionUnit[] {
		// process any condition sequences this sequence calls, producing a flat list - this means that replace() etc
		// can work on conditions within sub-sequences
		const expandedUnits = this.getCallablesWithSubSequencesExpanded();
		const toClass = AbstractConditionSequence.actionToConditionClass;

		// First check that all modifications refer to a condition in this sequence
		const conditionClasses = new Set(expandedUnits.map(toClass));
		const check = (map: Map<ConditionClass, unknown>, what: string) => {
			for (const conditionClass of map.keys()) {
				if (!conditionClasses.has(conditionClass)) {
					throw new Error(`${this.constructor.name}: ${what} requested for missing condition: ${conditionClass.name}`);
				}
			}
		};
		check(this.replacements, "replacement");
		check(this.skips, "skip");
		check(this._insertBefore, "insertion");
		check(this._insertAfter, "insertion");

		const units: TestExecutionUnit[] = [...this.before];
		for (let action of expandedUnits) {
			const conditionClass = toClass(action);
			if (conditionClass != null) {
				const replacement = this.replacements.get(conditionClass);
				const skipMessage = this.skips.get(conditionClass);
				const before = this._insertBefore.get(conditionClass);
				const after = this._insertAfter.get(conditionClass);
				if (replacement) {
					action = replacement;
				}
				if (skipMessage !== undefined) {
					action = new SkippedCondition(conditionClass.name, skipMessage);
				}
				if (before) {
					action = sequenceOf(before, action);
				}
				if (after) {
					action = sequenceOf(action, after);
				}
			}
			units.push(action);
		}
		units.push(...this.after);
		return units;
	}

	replace(conditionToReplace: ConditionClass, builder: TestExecutionUnit): ConditionSequence {
		this.replacements.set(conditionToReplace, builder);
		return this;
	}

	skip(conditionToSkip: ConditionClass, message: string): ConditionSequence {
		this.skips.set(conditionToSkip, message);
		return this;
	}

	insertBefore(conditionToInsertAt: ConditionClass, builder: TestExecutionUnit): ConditionSequence {
		this._insertBefore.set(conditionToInsertAt, builder);
		return this;
	}

	insertAfter(conditionToInsertAfter: ConditionClass, builder: TestExecutionUnit): ConditionSequence {
		this._insertAfter.set(conditionToInsertAfter, builder);
		return this;
	}

	then(...builders: TestExecutionUnit[]): ConditionSequence {
		this.after.push(...builders);
		return this;
	}

	butFirst(...builders: TestExecutionUnit[]): ConditionSequence {
		this.before.push(...builders);
		return this;
	}

	/**
	 * callAndStopOnFailure(condition, ...requirements)
	 * callAndStopOnFailure(condition, onFail, ...requirements)
	 */
	protected callAndStopOnFailure(condition: Condition | ConditionClass, ...rest: (string | ConditionResult)[]): void {
		const { onFail, requirements } = splitOnFail(rest, ConditionResult.FAILURE);
		this.call(this.condition(condition).requirements(requirements).onFail(onFail));
	}

	/**
	 * callAndContinueOnFailure(condition, ...requirements)  -> onFail INFO if no requirements, WARNING otherwise
	 * callAndContinueOnFailure(condition, onFail, ...requirements)
	 */
	protected callAndContinueOnFailure(
		condition: Condition | ConditionClass,
		...rest: (string | ConditionResult)[]
	): void {
		const { onFail, requirements } = splitOnFail(rest, implicitOnFail(rest));
		this.call(this.condition(condition).requirements(requirements).onFail(onFail).dontStopOnFailure());
	}
}

/** Create an anonymous sequence of the given units */
export function sequenceOf(...units: TestExecutionUnit[]): ConditionSequence {
	return new (class extends AbstractConditionSequence {
		evaluate(): void {
			this.call(units);
		}
	})();
}

/**
 * Split a Java-style varargs tail where the first element may be a ConditionResult.
 */
export function splitOnFail(
	rest: (string | ConditionResult)[],
	defaultOnFail: ConditionResult,
): { onFail: ConditionResult; requirements: string[] } {
	if (rest.length > 0 && isConditionResult(rest[0])) {
		return { onFail: rest[0], requirements: rest.slice(1) as string[] };
	}
	return { onFail: defaultOnFail, requirements: rest as string[] };
}

/** The onFail of Java's overloads without an explicit one: INFO without requirements, WARNING with requirements */
export function implicitOnFail(requirements: unknown[]): ConditionResult {
	return requirements.length === 0 ? ConditionResult.INFO : ConditionResult.WARNING;
}
