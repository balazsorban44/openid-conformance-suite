import type { Environment } from "./Environment.ts";
import type { TestInstanceEventLog } from "./EventLog.ts";
import type { TestLockManager } from "./TestLockManager.ts";
import { NamedError } from "./NamedError.ts";

/** Port of condition/Condition.java ConditionResult */
export const ConditionResult = {
	FAILURE: "FAILURE",
	WARNING: "WARNING",
	INFO: "INFO",
	SUCCESS: "SUCCESS",
	REVIEW: "REVIEW",
} as const;
export type ConditionResult = (typeof ConditionResult)[keyof typeof ConditionResult];

export function isConditionResult(v: unknown): v is ConditionResult {
	return typeof v === "string" && Object.prototype.hasOwnProperty.call(ConditionResult, v);
}

/**
 * Port of condition/PreEnvironment.java and PostEnvironment.java.
 * Declared as `static pre` / `static post` on a condition class (see AbstractCondition).
 */
export interface EnvironmentRequirements {
	required?: string[];
	strings?: string[];
	integers?: string[];
}

/** Port of condition/Condition.java */
export interface Condition {
	/** Setup everything the Condition needs to run; call before execute() */
	setProperties(
		testId: string,
		log: TestInstanceEventLog,
		conditionResultOnFailure: ConditionResult,
		requirements: string[],
	): void;
	/** Set the lock manager for releasing/reacquiring the test lock around blocking operations */
	setLockManager(lockManager: TestLockManager | null): void;
	execute(env: Environment): Promise<void>;
	/** Returns a string suitable for tagging this as a "source" in the logs, defaults to the class name */
	getMessage(): string;
}

/** A concrete condition class (Java: Class<? extends Condition>) */
export type ConditionClass = (new () => Condition) & { name: string };

/**
 * Port of condition/ConditionError.java
 *
 * Record a failure from a condition. This should only be created from the error() methods in
 * AbstractCondition, which will also add a log entry.
 */
export class ConditionError extends NamedError {
	readonly testId: string;
	readonly isPreOrPostError: boolean;

	constructor(testId: string, message: string, options?: { cause?: unknown; isPreOrPostError?: boolean }) {
		super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
		this.testId = testId;
		this.isPreOrPostError = options?.isPreOrPostError ?? false;
	}

	getTestId(): string {
		return this.testId;
	}
}
