import { ConditionResult, type Condition, type ConditionClass } from "./Condition.ts";

/** Marker for anything that can be passed to call() (port of testmodule/TestExecutionUnit.java) */
export interface TestExecutionUnit {
	readonly unitKind: string;
}

/**
 * Port of testmodule/ConditionCallBuilder.java
 *
 * Utility class to collect the attributes related to a Condition call, such as which class
 * to call, what to do on failure, when the call should be skipped.
 */
export class ConditionCallBuilder implements TestExecutionUnit {
	readonly unitKind = "condition";
	private readonly conditionClass: ConditionClass;
	private readonly condition: Condition | null;
	private readonly _requirements: string[] = [];
	private _onFail: ConditionResult = ConditionResult.FAILURE;
	private _onSkip: ConditionResult = ConditionResult.INFO;
	private stopOnFailure = true;
	private readonly _skipIfObjectsMissing: string[] = [];
	private readonly _skipIfStringsMissing: string[] = [];
	private readonly _skipIfStringsPresent: string[] = [];
	private readonly _skipIfLongsMissing: string[] = [];
	private readonly _skipIfElementsMissing: [string, string][] = [];
	private readonly _skipIfElementsPresent: [string, string][] = [];

	constructor(conditionOrClass: Condition | ConditionClass) {
		if (typeof conditionOrClass === "function") {
			this.conditionClass = conditionOrClass;
			this.condition = null;
		} else {
			this.condition = conditionOrClass;
			this.conditionClass = conditionOrClass.constructor as ConditionClass;
		}
	}

	/** Add a single requirement tag to this condition call, such as "OIDCC-2.1.2" */
	requirement(requirement: string): this {
		this._requirements.push(requirement);
		return this;
	}

	/** Add a list of requirement tags to this condition call */
	requirements(...requirements: (string | string[] | undefined | null)[]): this {
		for (const r of requirements.flat()) {
			if (r != null) {
				this._requirements.push(r);
			}
		}
		return this;
	}

	/** Set the result to log if the condition fails by throwing a ConditionError during evaluation. Defaults to FAILURE */
	onFail(onFail: ConditionResult): this {
		this._onFail = onFail;
		return this;
	}

	/** Set the result to log if the condition is skipped via one of the skip mechanisms. Defaults to INFO */
	onSkip(onSkip: ConditionResult): this {
		this._onSkip = onSkip;
		return this;
	}

	/** Indicate the test should continue execution even if the condition fails. */
	dontStopOnFailure(): this {
		this.stopOnFailure = false;
		return this;
	}

	skipIfObjectMissing(key: string): this {
		this._skipIfObjectsMissing.push(key);
		return this;
	}

	skipIfObjectsMissing(...keys: (string | string[] | null | undefined)[]): this {
		for (const k of keys.flat()) {
			if (k != null) {
				this._skipIfObjectsMissing.push(k);
			}
		}
		return this;
	}

	skipIfStringMissing(key: string): this {
		this._skipIfStringsMissing.push(key);
		return this;
	}

	skipIfLongMissing(key: string): this {
		this._skipIfLongsMissing.push(key);
		return this;
	}

	skipIfStringsMissing(...keys: (string | string[] | null | undefined)[]): this {
		for (const k of keys.flat()) {
			if (k != null) {
				this._skipIfStringsMissing.push(k);
			}
		}
		return this;
	}

	skipIfStringPresent(key: string): this {
		this._skipIfStringsPresent.push(key);
		return this;
	}

	skipIfStringsPresent(...keys: (string | string[] | null | undefined)[]): this {
		for (const k of keys.flat()) {
			if (k != null) {
				this._skipIfStringsPresent.push(k);
			}
		}
		return this;
	}

	skipIfLongsMissing(...keys: (string | string[] | null | undefined)[]): this {
		for (const k of keys.flat()) {
			if (k != null) {
				this._skipIfLongsMissing.push(k);
			}
		}
		return this;
	}

	/** Skip if the element at objId.path is missing (path in dot-separated format such as "foo.bar") */
	skipIfElementMissing(objId: string | null, path: string | null): this {
		if (objId != null && path != null) {
			this._skipIfElementsMissing.push([objId, path]);
		}
		return this;
	}

	skipIfElementPresent(objId: string | null, path: string | null): this {
		if (objId != null && path != null) {
			this._skipIfElementsPresent.push([objId, path]);
		}
		return this;
	}

	// getters

	getCondition(): Condition | null {
		return this.condition;
	}

	getConditionClass(): ConditionClass {
		return this.conditionClass;
	}

	getRequirements(): string[] {
		return [...this._requirements];
	}

	getOnFail(): ConditionResult {
		return this._onFail;
	}

	getOnSkip(): ConditionResult {
		return this._onSkip;
	}

	isStopOnFailure(): boolean {
		return this.stopOnFailure;
	}

	getSkipIfObjectsMissing(): string[] {
		return this._skipIfObjectsMissing;
	}

	getSkipIfStringsMissing(): string[] {
		return this._skipIfStringsMissing;
	}

	getSkipIfStringsPresent(): string[] {
		return this._skipIfStringsPresent;
	}

	getSkipIfLongsMissing(): string[] {
		return this._skipIfLongsMissing;
	}

	getSkipIfElementsMissing(): [string, string][] {
		return this._skipIfElementsMissing;
	}

	getSkipIfElementsPresent(): [string, string][] {
		return this._skipIfElementsPresent;
	}
}
