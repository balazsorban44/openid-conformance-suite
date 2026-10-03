import { ConditionError } from "./Condition.ts";
import { NamedError } from "./NamedError.ts";

export { NamedError };

/** Port of testmodule/TestInterruptedException.java */
export class TestInterruptedException extends NamedError {
	readonly testId: string | null;

	constructor(testId: string | null, msgOrCause: string | unknown, cause?: unknown) {
		if (typeof msgOrCause === "string") {
			super(msgOrCause, cause !== undefined ? { cause } : undefined);
		} else {
			super(messageOf(msgOrCause), { cause: msgOrCause });
		}
		this.testId = testId;
	}

	getTestId(): string | null {
		return this.testId;
	}
}

/**
 * Port of testmodule/TestFailureException.java
 *
 * General exception for anything that has gone wrong in a TestModule. A 'cause' of a ConditionError is a
 * special case: ConditionErrors should only be created by AbstractCondition's error() methods - these add
 * log messages meaning the rest of the suite can/should avoid creating further log messages for
 * TestFailureExceptions with causes of ConditionError.
 *
 * Constructors:
 *   new TestFailureException(conditionError)
 *   new TestFailureException(testId, msg)
 *   new TestFailureException(testId, cause)
 *   new TestFailureException(testId, msg, cause)
 *   TestFailureException.oauthError(testId, error, errorDescription)
 */
export class TestFailureException extends TestInterruptedException {
	errorDescription: string | null = null;

	constructor(causeOrTestId: ConditionError | string | null, msgOrCause?: string | unknown, cause?: unknown) {
		if (causeOrTestId instanceof ConditionError) {
			super(causeOrTestId.getTestId(), causeOrTestId);
		} else {
			super(causeOrTestId, msgOrCause, cause);
		}
	}

	/**
	 * Constructor overload to allow creating OAuth2 style error responses,
	 * ref https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.
	 */
	static oauthError(testId: string | null, error: string, errorDescription: string): TestFailureException {
		const e = new TestFailureException(testId, error);
		e.errorDescription = errorDescription;
		return e;
	}

	getError(): string {
		return this.message;
	}

	getErrorDescription(): string | null {
		return this.errorDescription;
	}
}

/** Port of testmodule/TestSkippedException.java */
export class TestSkippedException extends TestInterruptedException {}

export function messageOf(e: unknown): string {
	if (e instanceof Error) {
		return e.message;
	}
	return String(e);
}
