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

function actionToConditionClass(action: TestExecutionUnit): ConditionClass | null {
	if (action instanceof ConditionCallBuilder) {
		return action.getConditionClass();
	}
	const c = action as unknown as Condition;
	if (typeof c.execute === "function" && typeof c.setProperties === "function") {
		return action.constructor as ConditionClass;
	}
	return null;
}

function isSequence(u: unknown): u is ConditionSequence {
	return (
		typeof u === "object" &&
		u !== null &&
		typeof (u as ConditionSequence).evaluate === "function" &&
		typeof (u as ConditionSequence).getTestExecutionUnits === "function"
	);
}

/**
 * Port of sequence/AbstractConditionSequence.java
 *
 * A sequence records calls (it does not execute them); evaluate() is synchronous and only builds the list.
 * The test module executes the resulting units.
 */
export abstract class AbstractConditionSequence implements ConditionSequence {
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
			if (action instanceof ConditionSequenceCallBuilder) {
				sequence = action.create();
			} else if (isSequence(action)) {
				sequence = action;
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

		// First check that all modifications refer to a condition in this sequence
		const conditionClasses = new Set<ConditionClass>();
		for (const u of expandedUnits) {
			const c = actionToConditionClass(u);
			if (c != null) {
				conditionClasses.add(c);
			}
		}
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
			const conditionClass = actionToConditionClass(action);
			if (conditionClass != null) {
				if (this.replacements.has(conditionClass)) {
					action = this.replacements.get(conditionClass) as TestExecutionUnit;
				}
				if (this.skips.has(conditionClass)) {
					action = new SkippedCondition(conditionClass.name, this.skips.get(conditionClass) as string);
				}
				if (this._insertBefore.has(conditionClass)) {
					action = sequenceOf(this._insertBefore.get(conditionClass) as TestExecutionUnit, action);
				}
				if (this._insertAfter.has(conditionClass)) {
					action = sequenceOf(action, this._insertAfter.get(conditionClass) as TestExecutionUnit);
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
		let onFail: ConditionResult;
		let requirements: string[];
		if (rest.length > 0 && isConditionResult(rest[0])) {
			onFail = rest[0];
			requirements = rest.slice(1) as string[];
		} else {
			requirements = rest as string[];
			onFail = requirements.length === 0 ? ConditionResult.INFO : ConditionResult.WARNING;
		}
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
