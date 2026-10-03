import assert from "node:assert/strict";
import { test } from "node:test";
import { setImmediate as tick } from "node:timers/promises";
import { ConditionError } from "./Condition.ts";
import { TestFailureException, TestInterruptedException, TestSkippedException } from "./exceptions.ts";
import { sleep, TestExecutionManager } from "./execution.ts";

function manager(testId = "t1") {
	const events: string[] = [];
	const errors: { error: TestInterruptedException; source: string }[] = [];
	const m = new TestExecutionManager(testId, {
		onError: async (error, source) => {
			events.push("onError");
			errors.push({ error, source });
		},
		afterTask: () => {
			events.push("afterTask");
		},
	});
	return { m, events, errors };
}

test("a successful task releases the lock once", async () => {
	const { m, events, errors } = manager();
	let ran = false;
	m.runInBackground(async () => {
		await tick();
		ran = true;
		return "done";
	});
	await m.drain();
	assert.equal(ran, true);
	assert.deepEqual(events, ["afterTask"]);
	assert.equal(errors.length, 0);
});

test("errors are wrapped and routed to onError after the lock is released", async () => {
	const { m, events, errors } = manager();
	const boom = new Error("boom");
	m.runInBackground(() => {
		throw boom;
	}, "my task");
	await m.drain();
	assert.deepEqual(events, ["afterTask", "onError", "afterTask"]);
	assert.equal(errors[0]?.source, "my task");
	const e = errors[0]?.error;
	assert.ok(e instanceof TestFailureException);
	assert.equal(e.message, "boom");
	assert.equal(e.cause, boom);
	assert.equal(e.getTestId(), "t1");
});

test("error wrapping rules", async () => {
	const { m, errors } = manager();
	const same = new TestSkippedException("t1", "skip");
	const nullId = new TestFailureException(null, "no id");
	const other = new TestFailureException("t2", "other");
	m.runInBackground(() => {
		throw same;
	});
	m.runInBackground(() => {
		throw nullId;
	});
	m.runInBackground(() => {
		throw other;
	});
	m.runInBackground(() => {
		throw new ConditionError("t1", "Cond: bad");
	});
	await m.drain();
	assert.equal(errors[0]?.error, same);
	assert.equal(errors[0]?.source, "background task");
	assert.equal(errors[1]?.error, nullId);
	assert.equal(
		errors[2]?.error.message,
		"A TestInterruptedException has been caught that does not contain the test id for the current test, this is a bug in the test module",
	);
	assert.equal(errors[2]?.error.cause, other);
	assert.equal(errors[2]?.error.getTestId(), "t1");
	assert.equal(
		errors[3]?.error.message,
		"A ConditionError has been incorrectly thrown by a TestModule, this is a bug in the test module: Cond: bad",
	);
	assert.equal(errors[3]?.error.cause, undefined);
	assert.ok(errors[3]?.error instanceof TestFailureException);
});

test("cancelled tasks are swallowed; drain does not wait for them", async () => {
	const { m, events, errors } = manager();
	let release!: () => void;
	const gate = new Promise<void>((r) => {
		release = r;
	});
	let sleeperRejected = false;
	m.runInBackground(async () => {
		try {
			await sleep(60_000, m.signal);
		} catch (e) {
			sleeperRejected = true;
			throw e;
		}
	});
	m.runInBackground(async () => {
		await gate; // ignores the signal
		throw new Error("after cancel");
	});
	assert.equal(m.signal.aborted, false);
	m.cancelAllBackgroundTasks();
	assert.equal(m.signal.aborted, true);
	await m.drain();
	await tick();
	assert.equal(sleeperRejected, true);
	release();
	await tick();
	await tick();
	assert.equal(errors.length, 0);
	assert.deepEqual(events, ["afterTask", "afterTask"]);
});

test("finalisation: runs once, is not cancelled, blocks runInBackground, and drain waits for it", async () => {
	const { m, errors } = manager();
	let finalised = 0;
	m.runFinalisationTaskInBackground(async () => {
		m.cancelAllBackgroundTasksExceptFinalisation();
		await sleep(5);
		finalised++;
		throw new Error("late");
	});
	m.runFinalisationTaskInBackground(() => {
		finalised += 100;
	});
	assert.throws(() => m.runInBackground(() => {}), {
		message: "runInBackground called after runFinalisationTaskInBackground()",
	});
	await m.drain();
	assert.equal(finalised, 1);
	// errors from the finalisation task are reported even though the signal was aborted
	assert.equal(errors[0]?.source, "finalisation");
	assert.equal(errors[0]?.error.message, "late");
});

test("scheduleInBackground waits, then runs; cancellation stops it", async () => {
	const { m } = manager();
	const started = Date.now();
	let at = 0;
	m.scheduleInBackground(() => {
		at = Date.now();
	}, 30);
	await m.drain();
	assert.ok(at - started >= 25, `ran after ${at - started}ms`);

	const second = manager();
	let ran = false;
	second.m.scheduleInBackground(() => {
		ran = true;
	}, 30);
	second.m.cancelAllBackgroundTasks();
	await sleep(50);
	assert.equal(ran, false);
	assert.equal(second.errors.length, 0);
});

test("sleep resolves, and rejects on abort (also when already aborted)", async () => {
	await sleep(1);
	await sleep(1, new AbortController().signal);
	const c = new AbortController();
	const p = sleep(60_000, c.signal);
	c.abort();
	await assert.rejects(p);
	await assert.rejects(sleep(1, c.signal));
});
