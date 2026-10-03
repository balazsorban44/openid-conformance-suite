/**
 * Checks: what upstream's AbstractCondition / callAndStopOnFailure / callAndContinueOnFailure / startBlock do, as
 * plain functions.
 *
 *   const c = condition("ValidateIdTokenNonce", "OIDCC-2");
 *   if (claims.nonce !== nonce) c.failure("Nonce values mismatch", { actual: claims.nonce, expected: nonce });
 *   c.success("Nonce values match", { nonce });
 *
 * A check function records its entries in the current test's log under its upstream condition name and throws
 * {@link ConditionFailed} on failure. Called directly the failure stops the test (callAndStopOnFailure); wrapped in
 * {@link soft} it is recorded and the test continues (callAndContinueOnFailure). The severity a failure is recorded
 * with is FAILURE unless soft() says otherwise ("warning", "info"), exactly like upstream's `onFail` result.
 */
import { currentContext, withContext, type LogFields, type Severity } from "./log.ts";

export type { Severity } from "./log.ts";

const SEVERITY_RESULT: Record<Severity, "FAILURE" | "WARNING" | "INFO"> = {
	failure: "FAILURE",
	warning: "WARNING",
	info: "INFO",
};

/** Thrown by a failing check; `soft()` swallows it, anything else lets it end the test */
export class ConditionFailed extends Error {
	readonly condition: string;
	/** The result the failure was recorded with */
	readonly result: "FAILURE" | "WARNING" | "INFO";

	constructor(condition: string, msg: string, result: "FAILURE" | "WARNING" | "INFO", cause?: unknown) {
		super(`${condition}: ${msg}`, cause === undefined ? undefined : { cause });
		this.name = "ConditionFailed";
		this.condition = condition;
		this.result = result;
	}
}

export interface Condition {
	readonly name: string;
	/** An entry without a result (upstream `log(msg, map)`; `log(map)` logs the fields without a message) */
	log(msg: string | LogFields, fields?: LogFields): void;
	success(msg: string, fields?: LogFields): void;
	info(msg: string, fields?: LogFields): void;
	warning(msg: string, fields?: LogFields): void;
	/** A REVIEW entry (upstream: a placeholder for an image/screenshot the tester has to check) */
	review(msg: string, fields?: LogFields): void;
	/** Records a failure at the current severity without stopping (a check that reports several problems, then fails) */
	logFailure(msg: string, fields?: LogFields): void;
	/** Records a failure at the current severity and throws ConditionFailed (upstream `throw error(...)`) */
	failure(msg: string, fields?: LogFields): never;
	/** failure() for a caught exception: adds error/error_class/cause fields as upstream's error(msg, cause, map) */
	failureFrom(msg: string, cause: unknown, fields?: LogFields): never;
}

/**
 * Starts a check named after its upstream condition. `requirements` are the spec references the entries cite (the
 * requirement strings upstream passes at the call site).
 */
export function condition(name: string, ...requirements: string[]): Condition {
	const ctx = currentContext();
	const log = ctx.log;
	const failureResult = SEVERITY_RESULT[ctx.severity];
	const record = (msg: string | undefined, fields: LogFields | undefined, result?: string) => {
		const entry: LogFields = { ...fields };
		if (msg !== undefined) {
			entry["msg"] = msg;
		}
		if (result) {
			entry["result"] = result;
		}
		if (requirements.length > 0 && !("requirements" in entry)) {
			entry["requirements"] = requirements;
		}
		log.log(name, entry);
	};
	return {
		name,
		log: (msg, fields) => (typeof msg === "string" ? record(msg, fields) : record(undefined, msg)),
		success: (msg, fields) => record(msg, fields, "SUCCESS"),
		info: (msg, fields) => record(msg, fields, "INFO"),
		warning: (msg, fields) => record(msg, fields, "WARNING"),
		review: (msg, fields) => record(msg, fields, "REVIEW"),
		logFailure: (msg, fields) => record(msg, fields, failureResult),
		failure(msg, fields) {
			record(msg, fields, failureResult);
			throw new ConditionFailed(name, msg, failureResult);
		},
		failureFrom(msg, cause, fields) {
			record(msg, { ...fields, ...errorFields(cause) }, failureResult);
			throw new ConditionFailed(name, msg, failureResult, cause);
		},
	};
}

/** The fields upstream adds for an exception (DataUtils.ex): error, error_class, cause, cause_class */
export function errorFields(e: unknown): LogFields {
	if (e == null) {
		return {};
	}
	const err = e instanceof Error ? e : new Error(String(e));
	const out: LogFields = { error: err.message, error_class: err.name };
	if (err.cause instanceof Error) {
		out["cause"] = err.cause.message;
		out["cause_class"] = err.cause.name;
	} else if (err.cause !== undefined) {
		out["cause"] = String(err.cause);
	}
	return out;
}

/**
 * Runs a check and continues on failure (upstream callAndContinueOnFailure). The failure is recorded with
 * `severity` ("failure" by default, "warning" or "info" to downgrade it) and the check returns undefined.
 */
export function soft<T>(fn: () => Promise<T>, severity?: Severity): Promise<T | undefined>;
export function soft<T>(fn: () => T, severity?: Severity): T | undefined;
export function soft<T>(
	fn: () => T | Promise<T>,
	severity: Severity = "failure",
): T | undefined | Promise<T | undefined> {
	const swallow = (e: unknown): undefined => {
		if (e instanceof ConditionFailed) {
			return undefined;
		}
		throw e;
	};
	try {
		const result = withContext({ severity }, fn);
		if (result instanceof Promise) {
			return result.catch(swallow);
		}
		return result;
	} catch (e) {
		return swallow(e);
	}
}

/**
 * A named block of the flow: a Playwright step in the report and a `-START-BLOCK-` entry (upstream
 * `eventLog.startBlock(name)` ... `endBlock()`) so every entry logged inside carries the block id.
 */
export async function block<T>(name: string, fn: () => T | Promise<T>): Promise<T> {
	const ctx = currentContext();
	return ctx.step(name, async () => {
		ctx.log.startBlock(name);
		try {
			return await fn();
		} finally {
			ctx.log.endBlock();
		}
	});
}

/**
 * Upstream's skipIfMissing/skipIfElementMissing: the check is not run because its input is absent, which is
 * logged as an INFO entry under the condition's name ("Skipped evaluation due to missing required ...").
 */
export function skipped(
	name: string,
	missing: { object: string } | { element: [string, string] } | { string: string },
	...requirements: string[]
): void {
	skippedWithResult("INFO", name, missing, ...requirements);
}

/** skipped() for a call whose `onSkip` is not INFO (upstream `.onSkip(ConditionResult.WARNING)`) */
export function skippedWithResult(
	result: "INFO" | "WARNING",
	name: string,
	missing: { object: string } | { element: [string, string] } | { string: string },
	...requirements: string[]
): void {
	const fields: LogFields =
		"object" in missing
			? { msg: "Skipped evaluation due to missing required object: " + missing.object, expected: missing.object }
			: "string" in missing
				? { msg: "Skipped evaluation due to missing required string: " + missing.string, expected: missing.string }
				: {
						msg: `Skipped evaluation due to missing required element: ${missing.element[0]} ${missing.element[1]}`,
						object: missing.element[0],
						path: missing.element[1],
					};
	fields["result"] = result;
	// upstream logs the requirements of a skipped call even when there are none
	fields["requirements"] = requirements;
	currentContext().log.log(name, fields);
}

/** Logs an entry under the test module's name (upstream `eventLog.log(getName(), ...)`) */
export function logModule(fields: LogFields | string): void {
	const ctx = currentContext();
	ctx.log.log(ctx.testName, fields);
}

/**
 * Upstream's fireTestSkipped(msg): logs the SKIPPED entry under the module's name. The test then ends with
 * Playwright's own skip (`skipTest(reason)` in tests/fixtures.ts, `rp.skipTest(reason)`).
 */
export function logTestSkipped(reason: string): void {
	logModule({ result: "SKIPPED", msg: "The test was skipped: " + reason });
}
