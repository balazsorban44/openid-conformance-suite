import assert from "node:assert/strict";
import { test } from "node:test";
import { AbstractCondition } from "./AbstractCondition.ts";
import { AbstractTestModule } from "./AbstractTestModule.ts";
import { BrowserControl } from "./BrowserControl.ts";
import { ConditionError, ConditionResult, type ConditionClass } from "./Condition.ts";
import { ConditionCallBuilder } from "./ConditionCallBuilder.ts";
import { args, type LogArgs } from "./DataUtils.ts";
import type { Environment } from "./Environment.ts";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";
import { TestExecutionManager } from "./execution.ts";
import { TestFailureException, TestSkippedException } from "./exceptions.ts";
import { ImageService } from "./ImageService.ts";
import { Result, Status, type PublishTestModule } from "./TestModule.ts";

/*
 * Pins the skip messages, the status machine, the result rules and handleException of AbstractTestModule.
 */

class Ok extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.logSuccess("ok");
		return env;
	}
}
class Fails extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error("fails", args("x", 1));
	}
}
class Crashes extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw new TypeError("crash");
	}
}

class M extends AbstractTestModule {
	static override readonly meta: PublishTestModule = { testName: "skip-test-module", displayName: "x", profile: "x" };
	override async configure(): Promise<void> {}
	override async start(): Promise<void> {}
	get environment(): Environment {
		return this.env;
	}
	run(b: ConditionCallBuilder): Promise<void> {
		return this.call(b);
	}
	skipMissing(...a: Parameters<AbstractTestModule["skipIfMissing"]>): Promise<void> {
		return this.skipIfMissing(...a);
	}
	skipElement(...a: Parameters<AbstractTestModule["skipIfElementMissing"]>): Promise<void> {
		return this.skipIfElementMissing(...a);
	}
	go(s: Status): Promise<void> {
		return this.setStatus(s);
	}
	/** the private status machine entry point (FINISHED/INTERRUPTED are reachable only through it) */
	internal(s: Status): Promise<void> {
		return (this as unknown as { setStatusInternal(s: Status): Promise<void> }).setStatusInternal(s);
	}
	resultFrom(r: ConditionResult): void {
		(
			this as unknown as { updateResultFromConditionFailure(r: ConditionResult): void }
		).updateResultFromConditionFailure(r);
	}
}

function create(): { m: M; log: TestInstanceEventLog; statuses: Status[] } {
	const log = new TestInstanceEventLog("tid");
	const m = new M();
	const statuses: Status[] = [];
	const exec = new TestExecutionManager("tid", { onError: async () => {}, afterTask: () => m.forceReleaseLock() });
	const images = new ImageService(log);
	const browser = new BrowserControl({}, "tid", log, exec, images, () => Promise.reject(new Error("no browser")));
	m.setProperties("tid", null, log, browser, exec, images, { onStatusChange: (s) => statuses.push(s) });
	return { m, log, statuses };
}

function body(e: LogEntry | undefined): LogArgs {
	assert.ok(e);
	const { _id, testId: _testId, time: _time, seq: _seq, ...rest } = e;
	return rest;
}

/** The entry as log.json has it, without the volatile members */
function json(e: LogEntry): string {
	return JSON.stringify(body(e));
}

function keys(o: object): string {
	return Object.keys(o).join(",");
}

const cond = (c: ConditionClass) => new ConditionCallBuilder(c);

test("the six skip messages", async () => {
	const { m, log } = create(); // CREATED: conditions may run (configure() runs in this state)
	m.environment.mapKey("alias", "obj");
	m.environment.putString("present", "x");
	m.environment.putObject("o", { p: 1 });
	await m.run(cond(Ok).skipIfObjectsMissing("obj").requirements("R-1"));
	await m.run(cond(Ok).skipIfStringsMissing("str").onSkip(ConditionResult.WARNING));
	await m.run(cond(Ok).skipIfStringsPresent("present"));
	await m.run(cond(Ok).skipIfLongsMissing("long"));
	await m.run(cond(Ok).skipIfElementMissing("obj", "a.b").requirements("R-2"));
	await m.run(cond(Ok).skipIfElementPresent("o", "p"));
	assert.equal(log.entries.length, 6);
	// as serialised into log.json (keys in order)
	assert.deepEqual(log.entries.map(json), [
		'{"src":"Ok","msg":"Skipped evaluation due to missing required object: obj","expected":"obj","result":"INFO","mapped":"obj","requirements":["R-1"]}',
		'{"src":"Ok","msg":"Skipped evaluation due to missing required string: str","expected":"str","result":"WARNING","requirements":[]}',
		'{"src":"Ok","msg":"Skipped evaluation because string is present: present","expected":"present","result":"INFO","requirements":[]}',
		'{"src":"Ok","msg":"Skipped evaluation due to missing required long integer: long","expected":"long","result":"INFO","requirements":[]}',
		'{"src":"Ok","msg":"Skipped evaluation due to missing required element: obj a.b","object":"obj","path":"a.b","mapped":"obj","result":"INFO","requirements":["R-2"]}',
		'{"src":"Ok","msg":"Skipped evaluation because element is present: o p","object":"o","path":"p","mapped":null,"result":"INFO","requirements":[]}',
	]);
	// a WARNING skip downgrades the result
	assert.equal(m.getResult(), Result.WARNING);
});

test("skipIfMissing / skipIfElementMissing defaults", async () => {
	const { m, log } = create();
	m.environment.putObject("have", {});
	await m.skipMissing(["have"], null, ConditionResult.INFO, Fails); // runs: onFail INFO
	await m.skipMissing(null, null, ConditionResult.INFO, Fails, "R-1"); // onFail WARNING with requirements
	await m.skipMissing(null, null, ConditionResult.INFO, Fails, ConditionResult.FAILURE, "R-2");
	await m.skipElement("have", "x", ConditionResult.FAILURE, Ok, ConditionResult.FAILURE, "R-3");
	assert.deepEqual(
		log.entries.map((e) => [e["result"], e["requirements"] ?? null]),
		[
			["INFO", null],
			["WARNING", ["R-1"]],
			["FAILURE", ["R-2"]],
			["FAILURE", ["R-3"]],
		],
	);
	assert.equal(log.entries[3]["msg"], "Skipped evaluation due to missing required element: have x");
	assert.equal(m.getResult(), Result.FAILED);
});

test("callCondition refuses to run outside RUNNING", async () => {
	const { m } = create();
	await m.go(Status.CONFIGURED);
	await assert.rejects(m.run(cond(Ok)), (e: unknown) => {
		assert.ok(e instanceof TestFailureException);
		assert.equal(
			e.message,
			"Condition 'Ok' called when test status is 'CONFIGURED'. This is a bug in the test module and probably means that a call to setStatus(Status.RUNNING) is missing.",
		);
		return true;
	});
});

test("condition failures: stop vs continue, framework exceptions", async () => {
	const { m, log } = create();
	await m.run(cond(Fails).onFail(ConditionResult.WARNING).dontStopOnFailure());
	assert.equal(m.getResult(), Result.WARNING);
	await assert.rejects(
		m.run(cond(Fails)),
		(e: unknown) => e instanceof TestFailureException && e.cause instanceof ConditionError,
	);
	assert.equal(m.getResult(), Result.WARNING); // the stop-on-failure result is set by handleException
	await assert.rejects(m.run(cond(Crashes).dontStopOnFailure()), { message: "crash" });
	const crash = log.entries.at(-1);
	assert.equal(crash?.src, "skip-test-module");
	assert.equal(crash?.["msg"], "Caught exception from test framework: crash");
	assert.equal(crash?.["error_class"], "TypeError");
});

const S = Status;
const ALLOWED: [Status, Status[]][] = [
	[S.CREATED, [S.CONFIGURED, S.WAITING, S.INTERRUPTED, S.FINISHED]],
	[S.CONFIGURED, [S.RUNNING, S.INTERRUPTED, S.FINISHED, S.WAITING]],
	[S.RUNNING, [S.INTERRUPTED, S.FINISHED, S.WAITING]],
	[S.WAITING, [S.RUNNING, S.INTERRUPTED, S.FINISHED]],
];
const PATH: Record<string, Status[]> = {
	CREATED: [],
	CONFIGURED: [S.CONFIGURED],
	RUNNING: [S.CONFIGURED, S.RUNNING],
	WAITING: [S.CONFIGURED, S.WAITING],
	FINISHED: [S.FINISHED],
	INTERRUPTED: [S.INTERRUPTED],
};

async function moduleAt(s: Status, keepServing = false): Promise<M> {
	const { m } = create();
	m.setKeepServingAfterFinish(keepServing);
	m.resultFrom(ConditionResult.WARNING); // FINISHED needs a known result
	for (const step of PATH[s]) {
		await m.internal(step);
	}
	assert.equal(m.getStatus(), s);
	return m;
}

async function illegal(m: M, to: Status): Promise<void> {
	const from = m.getStatus();
	await assert.rejects(m.internal(to), (e: unknown) => {
		assert.ok(e instanceof TestFailureException);
		assert.equal(e.message, `Illegal test state change: ${from} -> ${to}`);
		return true;
	});
	assert.equal(m.getStatus(), from);
}

test("status machine: allowed transitions", async () => {
	const { m, statuses } = create();
	assert.deepEqual(statuses, [S.CREATED]);
	assert.equal(m.getStatus(), S.CREATED);
	for (const [from, tos] of ALLOWED) {
		for (const to of tos) {
			const mm = await moduleAt(from);
			await mm.internal(to);
			assert.equal(mm.getStatus(), to);
		}
	}
	const finished = await moduleAt(S.FINISHED, true);
	await finished.internal(S.RUNNING);
	await finished.internal(S.FINISHED);
	await finished.internal(S.WAITING);
});

test("status machine: illegal transitions and messages", async () => {
	await illegal(await moduleAt(S.CREATED), S.RUNNING);
	await illegal(await moduleAt(S.RUNNING), S.CONFIGURED);
	await illegal(await moduleAt(S.WAITING), S.CONFIGURED);
	await illegal(await moduleAt(S.FINISHED), S.RUNNING);
	await illegal(await moduleAt(S.FINISHED), S.WAITING);
	await illegal(await moduleAt(S.INTERRUPTED), S.RUNNING);
	await illegal(await moduleAt(S.FINISHED, true), S.INTERRUPTED);
	await illegal(new M(), S.CONFIGURED); // NOT_YET_CREATED

	const waiting = await moduleAt(S.WAITING);
	await assert.rejects(waiting.internal(S.WAITING), {
		message: "setStatus() called but status is the same: WAITING -> WAITING",
	});
	await assert.rejects(waiting.go(S.FINISHED), {
		message:
			"Test module called setStatus() with a value other than CONFIGURED/WAITING/RUNNING. This is a bug in the test module; it should use a different method to change to the desired state - e.g. fireTestFinished() or throwing a TestFailureException.",
	});
	const { m } = create();
	await assert.rejects(m.internal(S.FINISHED), {
		message: "Illegal test state; tried to move from CREATED -> FINISHED but 'result' is UNKNOWN",
	});
});

test("result rules", async () => {
	const { m } = create();
	m.resultFrom(ConditionResult.INFO);
	assert.equal(m.getResult(), Result.UNKNOWN);
	m.resultFrom(ConditionResult.WARNING);
	assert.equal(m.getResult(), Result.WARNING);
	m.fireTestReviewNeeded();
	assert.equal(m.getResult(), Result.REVIEW);
	m.resultFrom(ConditionResult.WARNING); // REVIEW is kept
	assert.equal(m.getResult(), Result.REVIEW);
	m.resultFrom(ConditionResult.FAILURE);
	assert.equal(m.getResult(), Result.FAILED);
	m.resultFrom(ConditionResult.WARNING);
	m.fireTestReviewNeeded();
	assert.equal(m.getResult(), Result.FAILED);
	assert.throws(
		() => m.fireTestSkipped("cannot test"),
		(e: unknown) => {
			assert.ok(e instanceof TestSkippedException);
			assert.equal(e.message, "cannot test");
			assert.equal(e.getTestId(), "tid");
			return true;
		},
	);
	assert.equal(m.getResult(), Result.FAILED); // fireTestSkipped keeps FAILED

	const other = create().m;
	assert.throws(() => other.fireTestSkipped("x"), TestSkippedException);
	assert.equal(other.getResult(), Result.SKIPPED);

	// WARNING/REVIEW only become a verdict on completion: INTERRUPTED resets them
	const interrupted = await moduleAt(S.RUNNING);
	await interrupted.internal(S.INTERRUPTED);
	assert.equal(interrupted.getResult(), Result.UNKNOWN);
});

test("handleException: explicit failure message", async () => {
	const { m, log } = create();
	await m.handleException(new TestFailureException("tid", "explicit failure"), "the source");
	assert.equal(m.getStatus(), S.INTERRUPTED);
	assert.equal(m.getResult(), Result.FAILED);
	assert.deepEqual(log.entries.slice(0, 2).map(json), [
		'{"src":"skip-test-module","caught_at":"the source","msg":"explicit failure","error":"explicit failure","error_class":"TestFailureException","result":"FAILURE"}',
		`{"src":"skip-test-module","msg":"Test was interrupted before it could complete. The failure 'explicit failure' means the test cannot continue.","result":"INTERRUPTED"}`,
	]);
	assert.equal(log.entries[2]["msg"], "Final environment");
});

test("handleException: wrapped exception and condition error", async () => {
	const { m, log } = create();
	const e = new TestFailureException("tid", new Error("boom"));
	await m.handleException(e, "incoming HTTP request");
	assert.equal(
		keys(body(log.entries[0])),
		"src,caught_at,error,error_class,cause,cause_class,cause_stacktrace,result,msg,stacktrace",
	);
	assert.equal(log.entries[0]["msg"], "unexpected exception caught: boom");

	const second = create();
	const ce = new ConditionError("tid", "Fails: fails");
	await second.m.handleException(new TestFailureException(ce), "x");
	// a ConditionError was already logged by the condition: only the interruption entry
	assert.equal(
		second.log.entries[0]["msg"],
		"Test was interrupted before it could complete. The failure 'Fails: fails' means the test cannot continue.",
	);
	assert.equal(second.m.getResult(), Result.FAILED);
});
