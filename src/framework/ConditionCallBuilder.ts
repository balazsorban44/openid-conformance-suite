import { ConditionResult, type Condition, type ConditionClass } from "./Condition.ts";

/** What a TestExecutionUnit is; call() and the sequence expansion switch on it */
export type UnitKind = "condition" | "command" | "sequence" | "sequence-call" | "skipped";

/** Marker for anything that can be passed to call() (port of testmodule/TestExecutionUnit.java) */
export interface TestExecutionUnit {
	readonly unitKind: UnitKind;
}

/** A reason to skip a condition call (see AbstractTestModule.callCondition for the order they are checked in) */
export type Skip =
	| { kind: "objectMissing"; key: string }
	| { kind: "stringMissing"; key: string }
	| { kind: "stringPresent"; key: string }
	| { kind: "longMissing"; key: string }
	| { kind: "elementMissing"; key: string; path: string }
	| { kind: "elementPresent"; key: string; path: string };

type KeySkipKind = Exclude<Skip["kind"], "elementMissing" | "elementPresent">;
type Keys = (string | string[] | null | undefined)[];

/**
 * Port of testmodule/ConditionCallBuilder.java
 *
 * Utility class to collect the attributes related to a Condition call, such as which class
 * to call, what to do on failure, when the call should be skipped. The collected attributes are in `spec`.
 */
export class ConditionCallBuilder implements TestExecutionUnit {
	readonly unitKind = "condition";
	readonly conditionClass: ConditionClass;
	/** The instance to evaluate; null means a new instance of conditionClass */
	readonly condition: Condition | null;
	readonly spec: {
		requirements: string[];
		onFail: ConditionResult;
		onSkip: ConditionResult;
		stopOnFailure: boolean;
		skips: Skip[];
	} = {
		requirements: [],
		onFail: ConditionResult.FAILURE,
		onSkip: ConditionResult.INFO,
		stopOnFailure: true,
		skips: [],
	};

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
		this.spec.requirements.push(requirement);
		return this;
	}

	/** Add a list of requirement tags to this condition call */
	requirements(...requirements: Keys): this {
		this.spec.requirements.push(...nonNull(requirements));
		return this;
	}

	/** Set the result to log if the condition fails by throwing a ConditionError during evaluation. Defaults to FAILURE */
	onFail(onFail: ConditionResult): this {
		this.spec.onFail = onFail;
		return this;
	}

	/** Set the result to log if the condition is skipped via one of the skip mechanisms. Defaults to INFO */
	onSkip(onSkip: ConditionResult): this {
		this.spec.onSkip = onSkip;
		return this;
	}

	/** Indicate the test should continue execution even if the condition fails. */
	dontStopOnFailure(): this {
		this.spec.stopOnFailure = false;
		return this;
	}

	skipIfObjectMissing(key: string): this {
		return this.skip("objectMissing", key);
	}

	skipIfObjectsMissing(...keys: Keys): this {
		return this.skip("objectMissing", ...nonNull(keys));
	}

	skipIfStringMissing(key: string): this {
		return this.skip("stringMissing", key);
	}

	skipIfStringsMissing(...keys: Keys): this {
		return this.skip("stringMissing", ...nonNull(keys));
	}

	skipIfStringPresent(key: string): this {
		return this.skip("stringPresent", key);
	}

	skipIfStringsPresent(...keys: Keys): this {
		return this.skip("stringPresent", ...nonNull(keys));
	}

	skipIfLongMissing(key: string): this {
		return this.skip("longMissing", key);
	}

	skipIfLongsMissing(...keys: Keys): this {
		return this.skip("longMissing", ...nonNull(keys));
	}

	/** Skip if the element at objId.path is missing (path in dot-separated format such as "foo.bar") */
	skipIfElementMissing(objId: string | null, path: string | null): this {
		if (objId != null && path != null) {
			this.spec.skips.push({ kind: "elementMissing", key: objId, path });
		}
		return this;
	}

	skipIfElementPresent(objId: string | null, path: string | null): this {
		if (objId != null && path != null) {
			this.spec.skips.push({ kind: "elementPresent", key: objId, path });
		}
		return this;
	}

	private skip(kind: KeySkipKind, ...keys: string[]): this {
		for (const key of keys) {
			this.spec.skips.push({ kind, key });
		}
		return this;
	}
}

function nonNull(keys: Keys): string[] {
	return keys.flat().filter((k) => k != null);
}
