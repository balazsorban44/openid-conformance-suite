import assert from "node:assert/strict";
import { test } from "node:test";
import { setImmediate as tick } from "node:timers/promises";
import { AbstractCondition } from "./AbstractCondition.ts";
import { AbstractConditionSequence } from "./AbstractConditionSequence.ts";
import { AbstractTestModule } from "./AbstractTestModule.ts";
import { BrowserControl } from "./BrowserControl.ts";
import { ConditionResult, type Condition, type ConditionClass, type EnvironmentRequirements } from "./Condition.ts";
import type { ConditionCallBuilder, TestExecutionUnit } from "./ConditionCallBuilder.ts";
import type { ConditionSequence, ConditionSequenceClass, ConditionSequenceSupplier } from "./ConditionSequence.ts";
import { args } from "./DataUtils.ts";
import type { Environment } from "./Environment.ts";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";
import { TestFailureException } from "./exceptions.ts";
import { TestExecutionManager } from "./execution.ts";
import { ImageService } from "./ImageService.ts";
import type { JsonObject } from "./json.ts";
import { Result, Status, type PublishTestModule } from "./TestModule.ts";
import type { TestLockManager } from "./TestLockManager.ts";

class PutsValue extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["value"] };
	override evaluate(env: Environment): Environment {
		env.putString("value", "v");
		this.logSuccess("put value", args("value", "v"));
		return env;
	}
}

class AlwaysFails extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error("this always fails", args("x", 1));
	}
}

class AlwaysWarns extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error("this always warns");
	}
}

class NeedsMissing extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["does_not_exist"] };
	override evaluate(env: Environment): Environment {
		return env;
	}
}

/** Captures the lock manager the module hands to conditions */
class LockProbe extends AbstractCondition {
	static lockManager: TestLockManager | null = null;
	override setLockManager(lockManager: TestLockManager | null): void {
		LockProbe.lockManager = lockManager;
		super.setLockManager(lockManager);
	}
	override evaluate(env: Environment): Environment {
		return env;
	}
}

class Seq extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(PutsValue, "REQ-1");
		this.callAndContinueOnFailure(AlwaysFails, ConditionResult.WARNING, "REQ-2");
	}
}

class Module extends AbstractTestModule {
	static override readonly meta: PublishTestModule = { testName: "unit-test-module", displayName: "x", profile: "x" };
	stopAtFailure = false;

	override async configure(config: JsonObject, baseUrl: string, _ext: string, _mtls: string): Promise<void> {
		this.env.putObject("config", config);
		this.env.putString("base_url", baseUrl);
		await this.setStatus(Status.CONFIGURED);
		this.fireSetupDone();
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.call(this.sequence(Seq));
		await this.skipIfMissing(["nope"], null, ConditionResult.INFO, PutsValue);
		if (this.stopAtFailure) {
			await this.callAndStopOnFailure(NeedsMissing);
		}
		await this.fireTestFinished();
	}
}

/**
 * A module whose configure/start/cleanup run test-supplied bodies, with public wrappers around the protected
 * framework API.
 */
class Harness extends AbstractTestModule {
	static override readonly meta: PublishTestModule = { testName: "harness", displayName: "x", profile: "x" };
	configureBody: (h: Harness) => Promise<void> = async () => {};
	body: (h: Harness) => Promise<void> = async () => {};
	cleanupBody: ((h: Harness) => Promise<void>) | null = null;
	lockTimeoutSeconds = 90;
	cleanupCalls = 0;

	override async configure(_config: JsonObject, baseUrl: string, _ext: string, _mtls: string): Promise<void> {
		this.env.putString("base_url", baseUrl);
		await this.configureBody(this);
		await this.setStatus(Status.CONFIGURED);
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);
		await this.body(this);
		await this.fireTestFinished();
	}

	override async cleanup(): Promise<void> {
		this.cleanupCalls++;
		await this.cleanupBody?.(this);
	}

	protected override getLockAcquireTimeoutSeconds(): number {
		return this.lockTimeoutSeconds;
	}

	get e(): Environment {
		return this.env;
	}
	run(u: TestExecutionUnit | ConditionSequence | null | undefined): Promise<void> {
		return this.call(u);
	}
	cond(c: Condition | ConditionClass): ConditionCallBuilder {
		return this.condition(c);
	}
	cmd() {
		return this.exec();
	}
	seq(s: ConditionSequenceClass | ConditionSequenceSupplier) {
		return this.sequence(s);
	}
	seqOf(...u: TestExecutionUnit[]) {
		return this.sequenceOf(...u);
	}
	setS(s: Status): Promise<void> {
		return this.setStatus(s);
	}
	stopOnFailure(c: ConditionClass, ...rest: (string | ConditionResult)[]): Promise<void> {
		return this.callAndStopOnFailure(c, ...rest);
	}
	continueOnFailure(c: ConditionClass, onFail: ConditionResult, ...reqs: string[]): Promise<void> {
		return this.callAndContinueOnFailure(c, onFail, ...reqs);
	}
	skipMissing(
		required: string[] | null,
		strings: string[] | null,
		onSkip: ConditionResult,
		c: ConditionClass,
		...rest: (string | ConditionResult)[]
	): Promise<void> {
		return this.skipIfMissing(required, strings, onSkip, c, ...rest);
	}
	skipElementMissing(
		o: string,
		p: string,
		onSkip: ConditionResult,
		c: ConditionClass,
		onFail: ConditionResult,
		...reqs: string[]
	): Promise<void> {
		return this.skipIfElementMissing(o, p, onSkip, c, onFail, ...reqs);
	}
}

interface Wired<M extends AbstractTestModule> {
	m: M;
	log: TestInstanceEventLog;
	exec: TestExecutionManager;
	images: ImageService;
}

/** The one place that wires a module into the framework (the attach API) */
function wire<M extends AbstractTestModule>(m: M, testId = "t1"): Wired<M> {
	const log = new TestInstanceEventLog(testId);
	const exec = new TestExecutionManager(testId, {
		onError: (e, src) => m.handleException(e, src),
		afterTask: () => m.forceReleaseLock(),
	});
	const images = new ImageService(log);
	const browser = new BrowserControl({}, testId, log, exec, images, () => Promise.reject(new Error("no browser")));
	m.attach({ id: testId, owner: null, eventLog: log, browser, executionManager: exec, imageService: images });
	return { m, log, exec, images };
}

async function runToEnd<M extends AbstractTestModule>(m: M): Promise<Wired<M>> {
	const w = wire(m);
	w.exec.runInBackground(async () => {
		await m.configure({}, "http://localhost/test/t1", "", "");
		await m.start();
	}, "test");
	await m.whenFinished();
	await w.exec.drain();
	return w;
}

async function runHarness(
	body: (h: Harness) => Promise<void>,
	setup: (h: Harness) => void = () => {},
): Promise<Wired<Harness>> {
	const h = new Harness();
	h.body = body;
	setup(h);
	return runToEnd(h);
}

const META = new Set(["_id", "testId", "time", "seq", "blockId"]);
/** A log entry without its per-run metadata, as [key, value] pairs in insertion order */
function strip(e: LogEntry | undefined): [string, unknown][] {
	assert.ok(e, "missing log entry");
	return Object.entries(e).filter(([k]) => !META.has(k));
}

async function runModule(stopAtFailure: boolean): Promise<{ m: Module; log: TestInstanceEventLog }> {
	const m = new Module();
	m.stopAtFailure = stopAtFailure;
	return runToEnd(m);
}

test("module runs sequence, records warning and finishes", async () => {
	const { m, log } = await runModule(false);
	assert.equal(m.getStatus(), Status.FINISHED);
	assert.equal(m.getResult(), Result.WARNING);
	const srcs = log.entries.map((e) => e.src);
	assert.ok(srcs.includes("PutsValue"));
	assert.ok(srcs.includes("AlwaysFails"));
	const fail = log.entries.find((e) => e.src === "AlwaysFails");
	assert.equal(fail?.["result"], "WARNING");
	assert.deepEqual(fail?.["requirements"], ["REQ-2"]);
	const skip = log.entries.find((e) => e.src === "PutsValue" && String(e["msg"]).startsWith("Skipped"));
	assert.ok(skip);
	assert.ok(log.entries.some((e) => e["msg"] === "Test has run to completion"));
});

test("stop-on-failure pre-environment error fails and interrupts the module", async () => {
	const { m, log } = await runModule(true);
	assert.equal(m.getStatus(), Status.INTERRUPTED);
	assert.equal(m.getResult(), Result.FAILED);
	assert.ok(log.entries.some((e) => e.src === "NeedsMissing" && e["result"] === "FAILURE"));
});

test("skip checks: messages, keys and evaluation order by kind (not by call order)", async () => {
	const { m, log } = await runHarness(async (h) => {
		const builder = () =>
			h
				.cond(PutsValue)
				.skipIfElementPresent("o", "p")
				.skipIfElementMissing("o", "q")
				.skipIfLongMissing("l")
				.skipIfStringPresent("sp")
				.skipIfStringMissing("sm")
				.skipIfObjectMissing("om")
				.onSkip(ConditionResult.INFO)
				.requirements("R-1", "R-2")
				.dontStopOnFailure();
		h.e.putString("sp", "x");
		h.e.putObject("o", { p: 1 });
		await h.run(builder()); // object missing
		h.e.putObject("om", {});
		await h.run(builder()); // string missing
		h.e.putString("sm", "x");
		await h.run(builder()); // string present
		h.e.removeNativeValue("sp");
		await h.run(builder()); // long missing
		h.e.putLong("l", 1);
		await h.run(builder()); // element missing
		h.e.putObject("o", { p: 1, q: 1 });
		await h.run(builder()); // element present
		h.e.putObject("o", { q: 1 });
		await h.run(builder()); // runs
	});
	const reqs = ["R-1", "R-2"];
	const skips = log.entries.filter((e) => String(e["msg"]).startsWith("Skipped")).map(strip);
	assert.deepEqual(skips, [
		[
			["src", "PutsValue"],
			["msg", "Skipped evaluation due to missing required object: om"],
			["expected", "om"],
			["result", "INFO"],
			["mapped", null],
			["requirements", reqs],
		],
		[
			["src", "PutsValue"],
			["msg", "Skipped evaluation due to missing required string: sm"],
			["expected", "sm"],
			["result", "INFO"],
			["requirements", reqs],
		],
		[
			["src", "PutsValue"],
			["msg", "Skipped evaluation because string is present: sp"],
			["expected", "sp"],
			["result", "INFO"],
			["requirements", reqs],
		],
		[
			["src", "PutsValue"],
			["msg", "Skipped evaluation due to missing required long integer: l"],
			["expected", "l"],
			["result", "INFO"],
			["requirements", reqs],
		],
		[
			["src", "PutsValue"],
			["msg", "Skipped evaluation due to missing required element: o q"],
			["object", "o"],
			["path", "q"],
			["mapped", null],
			["result", "INFO"],
			["requirements", reqs],
		],
		[
			["src", "PutsValue"],
			["msg", "Skipped evaluation because element is present: o p"],
			["object", "o"],
			["path", "p"],
			["mapped", null],
			["result", "INFO"],
			["requirements", reqs],
		],
	]);
	assert.ok(log.entries.some((e) => e.src === "PutsValue" && e["msg"] === "put value"));
	assert.equal(m.getResult(), Result.PASSED);
});

test("skip checks: the first missing key of a kind wins, mapped keys are reported, onSkip feeds the result", async () => {
	const { m, log } = await runHarness(async (h) => {
		h.e.mapKey("alias", "real");
		await h.run(h.cond(PutsValue).skipIfObjectsMissing(["a1"], null, "a2").onSkip(ConditionResult.WARNING));
		await h.run(h.cond(PutsValue).skipIfObjectMissing("real")); // "real" is shadowed (a mapKey target)
		await h.run(h.cond(PutsValue).skipIfElementMissing("real", "x.y"));
		await h.run(h.cond(PutsValue).skipIfStringsMissing("s1", ["s2"]));
		await h.run(h.cond(PutsValue).skipIfElementMissing(null, "x").skipIfElementPresent("x", null));
	});
	const skips = log.entries.filter((e) => String(e["msg"]).startsWith("Skipped"));
	assert.deepEqual(
		skips.map((e) => [e["msg"], e["mapped"], e["result"]]),
		[
			["Skipped evaluation due to missing required object: a1", null, "WARNING"],
			["Skipped evaluation due to missing required object: real", "real", "INFO"],
			["Skipped evaluation due to missing required element: real x.y", "real", "INFO"],
			["Skipped evaluation due to missing required string: s1", undefined, "INFO"],
		],
	);
	// null objId/path are ignored, so the last call runs the condition
	assert.equal(log.entries.filter((e) => e["msg"] === "put value").length, 1);
	assert.equal(m.getResult(), Result.WARNING);
});

test("skipIfMissing / skipIfElementMissing / callAndContinueOnFailure severities", async () => {
	const { m, log } = await runHarness(async (h) => {
		await h.skipMissing(null, null, ConditionResult.INFO, AlwaysFails); // INFO
		await h.skipMissing(null, null, ConditionResult.INFO, AlwaysFails, "R-1"); // WARNING
		await h.skipMissing(null, null, ConditionResult.INFO, AlwaysFails, ConditionResult.FAILURE, "R-2"); // FAILURE
		await h.skipElementMissing("x", "y", ConditionResult.WARNING, AlwaysFails, ConditionResult.FAILURE, "R-3");
		await h.continueOnFailure(AlwaysWarns, ConditionResult.WARNING, "R-4");
	});
	const fails = log.entries.filter((e) => e.src === "AlwaysFails" || e.src === "AlwaysWarns");
	assert.deepEqual(
		fails.map((e) => [e.src, e["result"], e["requirements"]]),
		[
			["AlwaysFails", "INFO", undefined],
			["AlwaysFails", "WARNING", ["R-1"]],
			["AlwaysFails", "FAILURE", ["R-2"]],
			["AlwaysFails", "WARNING", ["R-3"]],
			["AlwaysWarns", "WARNING", ["R-4"]],
		],
	);
	assert.equal(fails[3]?.["msg"], "Skipped evaluation due to missing required element: x y");
	// FAILURE then WARNING: stays FAILED
	assert.equal(m.getResult(), Result.FAILED);
	assert.equal(m.getStatus(), Status.FINISHED);
});

test("callAndStopOnFailure: onFail must be FAILURE; failure messages and interruption", async () => {
	const { m, log } = await runHarness(async (h) => {
		await h.stopOnFailure(PutsValue, ConditionResult.WARNING, "R-1");
	});
	assert.equal(m.getStatus(), Status.INTERRUPTED);
	assert.equal(m.getResult(), Result.FAILED);
	const caught = log.entries.find((e) => e["caught_at"] === "test");
	assert.equal(caught?.["msg"], "callAndStopOnFailure called with onFail != ConditionResult.FAILURE");
	assert.equal(caught?.["error_class"], "TestFailureException");
	const interrupted = log.entries.find((e) => String(e["msg"]).startsWith("Test was interrupted"));
	assert.deepEqual(strip(interrupted), [
		["src", "harness"],
		[
			"msg",
			"Test was interrupted before it could complete. The failure 'callAndStopOnFailure called with onFail != ConditionResult.FAILURE' means the test cannot continue.",
		],
		["result", "INTERRUPTED"],
	]);
	assert.equal(log.entries.at(-1)?.["msg"], "Final environment");
	assert.ok(!log.entries.some((e) => e["msg"] === "Test has run to completion"));
});

test("an unexpected error is logged with its cause", async () => {
	const { m, log } = await runHarness(async () => {
		throw new Error("boom");
	});
	assert.equal(m.getStatus(), Status.INTERRUPTED);
	assert.equal(m.getResult(), Result.FAILED);
	const caught = log.entries.find((e) => e["caught_at"] === "test");
	assert.equal(caught?.["msg"], "unexpected exception caught: boom");
	assert.equal(caught?.["cause"], "boom");
	assert.ok(
		log.entries.some(
			(e) =>
				e["msg"] ===
				"Test was interrupted before it could complete. The failure 'boom' means the test cannot continue.",
		),
	);
});

test("a condition failure with stop-on-failure interrupts without a caught_at entry", async () => {
	const { m, log } = await runHarness(async (h) => {
		await h.stopOnFailure(AlwaysFails, "R-1");
	});
	assert.equal(m.getResult(), Result.FAILED);
	assert.ok(!log.entries.some((e) => "caught_at" in e));
	assert.ok(
		log.entries.some(
			(e) =>
				e["msg"] ===
				"Test was interrupted before it could complete. The failure 'AlwaysFails: this always fails' means the test cannot continue.",
		),
	);
});

test("conditions are refused unless RUNNING, CREATED or during cleanup", async () => {
	const errors: string[] = [];
	const { m, log } = await runHarness(
		async (h) => {
			await h.setS(Status.WAITING);
			try {
				await h.run(h.cond(PutsValue));
			} catch (e) {
				assert.ok(e instanceof TestFailureException);
				errors.push(e.message);
			}
			await h.setS(Status.RUNNING);
		},
		(h) => {
			h.configureBody = async (x) => {
				await x.run(x.cond(PutsValue)); // CREATED: allowed
			};
			h.cleanupBody = async (x) => {
				await x.run(x.cond(LockProbe)); // during cleanup: allowed
				// the lock manager is disabled before cleanup, so this does not change the status
				await LockProbe.lockManager?.releaseLock();
				errors.push("cleanup status " + x.getStatus());
			};
		},
	);
	assert.deepEqual(errors, [
		"Condition 'PutsValue' called when test status is 'WAITING'. This is a bug in the test module and probably means that a call to setStatus(Status.RUNNING) is missing.",
		"cleanup status WAITING",
	]);
	assert.equal(m.getStatus(), Status.FINISHED);
	assert.equal(m.cleanupCalls, 1);
	assert.equal(log.entries.filter((e) => e["msg"] === "put value").length, 1);
});

test("status machine: setStatus restrictions, same-status and illegal transitions", async () => {
	const errors: string[] = [];
	const attempt = async (f: () => Promise<unknown>) => {
		try {
			await f();
			errors.push("ok");
		} catch (e) {
			errors.push((e as Error).message);
		}
	};
	const { m } = await runHarness(async (h) => {
		await attempt(() => h.setS(Status.FINISHED));
		await attempt(() => h.setS(Status.INTERRUPTED));
		await h.setS(Status.WAITING);
		await attempt(() => h.setS(Status.WAITING));
		await attempt(() => h.setS(Status.CONFIGURED));
		await h.setS(Status.RUNNING);
		h.lockTimeoutSeconds = 0.05;
		// RUNNING -> RUNNING from the flow that holds the lock times out waiting for it
		await attempt(() => h.setS(Status.RUNNING));
		h.lockTimeoutSeconds = 90;
	});
	assert.deepEqual(errors, [
		"Test module called setStatus() with a value other than CONFIGURED/WAITING/RUNNING. This is a bug in the test module; it should use a different method to change to the desired state - e.g. fireTestFinished() or throwing a TestFailureException.",
		"Test module called setStatus() with a value other than CONFIGURED/WAITING/RUNNING. This is a bug in the test module; it should use a different method to change to the desired state - e.g. fireTestFinished() or throwing a TestFailureException.",
		"setStatus() called but status is the same: WAITING -> WAITING",
		"Illegal test state change: WAITING -> CONFIGURED",
		"Timed out after 0.05 seconds waiting to acquire the test lock; another thread is holding it and is probably stuck. This may be a bug in the test suite. Aborting.",
	]);
	assert.equal(m.getStatus(), Status.FINISHED);
	assert.equal(m.getResult(), Result.PASSED);
});

test("status machine: FINISHED -> RUNNING/WAITING only with keepServingAfterFinish", async () => {
	const { m } = await runHarness(async () => {});
	await assert.rejects(m.setS(Status.RUNNING), { message: "Illegal test state change: FINISHED -> RUNNING" });
	const k = await runHarness(async () => {});
	k.m.setKeepServingAfterFinish(true);
	await k.m.setS(Status.RUNNING);
	assert.equal(k.m.getStatus(), Status.RUNNING);
	await k.m.setS(Status.WAITING);
	assert.equal(k.m.getStatus(), Status.WAITING);
	const k2 = await runHarness(async () => {});
	k2.m.setKeepServingAfterFinish(true);
	await assert.rejects(k2.m.setS(Status.CONFIGURED), {
		message: "Illegal test state change: FINISHED -> CONFIGURED",
	});
	assert.equal(m.getStatus(), Status.FINISHED);
});

test("status machine: CREATED/CONFIGURED transitions", async () => {
	const h = new Harness();
	wire(h);
	assert.equal(h.getStatus(), Status.CREATED);
	await assert.rejects(h.setS(Status.RUNNING), { message: "Illegal test state change: CREATED -> RUNNING" });
	await h.setS(Status.CONFIGURED);
	await assert.rejects(h.setS(Status.CONFIGURED), {
		message: "setStatus() called but status is the same: CONFIGURED -> CONFIGURED",
	});
	await h.setS(Status.WAITING);
	assert.equal(h.getStatus(), Status.WAITING);
});

test("lock: RUNNING holds it, WAITING releases it; the lock manager releases/reacquires around I/O", async () => {
	const h = new Harness();
	wire(h);
	await h.configure({}, "http://x", "", "");
	await h.setS(Status.RUNNING); // flow A holds the lock
	let bRunning = false;
	const b = h.setS(Status.RUNNING).then(() => {
		bRunning = true;
	});
	await tick();
	await tick();
	assert.equal(bRunning, false);
	await h.setS(Status.WAITING); // A releases
	await b;
	assert.equal(bRunning, true);
	assert.equal(h.getStatus(), Status.RUNNING);

	// the lock manager handed to conditions: release -> WAITING, reacquire -> RUNNING
	await h.run(h.cond(LockProbe));
	const lm = LockProbe.lockManager;
	assert.ok(lm);
	await lm.releaseLock();
	assert.equal(h.getStatus(), Status.WAITING);
	// another flow can run while the lock is released; reacquireLock only acts on WAITING
	await h.setS(Status.RUNNING);
	await lm.reacquireLock();
	assert.equal(h.getStatus(), Status.RUNNING);
	await h.setS(Status.WAITING);
	await lm.reacquireLock();
	assert.equal(h.getStatus(), Status.RUNNING);
	// releaseLock is a no-op unless RUNNING
	await h.setS(Status.WAITING);
	await lm.releaseLock();
	assert.equal(h.getStatus(), Status.WAITING);
});

test("finalisation: cleanup runs before the status changes, then completion and the final environment", async () => {
	let statusDuringCleanup: string | null = null;
	let finishedDuringCleanup = false;
	const { m, log } = await runHarness(
		async (h) => {
			h.e.putString("k", "v");
		},
		(h) => {
			h.cleanupBody = async (x) => {
				statusDuringCleanup = x.getStatus();
				let resolved = false;
				void x.whenFinished().then(() => {
					resolved = true;
				});
				await tick();
				finishedDuringCleanup = resolved;
			};
		},
	);
	assert.equal(statusDuringCleanup, Status.WAITING);
	assert.equal(finishedDuringCleanup, false);
	assert.equal(m.cleanupCalls, 1);
	const tail = log.entries.slice(-2).map(strip);
	assert.deepEqual(tail[0], [
		["src", "harness"],
		["msg", "Test has run to completion"],
		["result", "FINISHED"],
		["testmodule_result", "PASSED"],
	]);
	assert.deepEqual(
		tail[1]?.filter(([k]) => k !== "env"),
		[
			["src", "harness"],
			["msg", "Final environment"],
			["final_env", true],
		],
	);
	assert.deepEqual(
		tail[1]?.map(([k]) => k),
		["src", "msg", "env", "final_env"],
	);
	// stop() after FINISHED logs nothing and does not run cleanup again
	const count = log.entries.length;
	await m.stop("again");
	assert.equal(log.entries.length, count);
	assert.equal(m.cleanupCalls, 1);
	assert.ok(!log.entries.some((e) => String(e["msg"]).startsWith("Test was interrupted")));
});

test("a test failure during cleanup is logged and does not prevent finishing", async () => {
	const { m, log } = await runHarness(
		async () => {},
		(h) => {
			h.cleanupBody = async (x) => {
				throw new TestFailureException(x.getId(), "cleanup broke");
			};
		},
	);
	assert.equal(m.getStatus(), Status.FINISHED);
	const e = log.entries.find((x) => x["msg"] === "A test failure was raised while cleaning up");
	assert.equal(e?.["error"], "cleanup broke");
	assert.equal(e?.["result"], "FAILURE");
});

test("result rules: skipped, review, warning reset on interruption", async () => {
	// fireTestSkipped -> SKIPPED, logged, then finished
	const skipped = await runHarness(async (h) => {
		h.fireTestSkipped("not supported");
	});
	assert.equal(skipped.m.getResult(), Result.SKIPPED);
	assert.equal(skipped.m.getStatus(), Status.FINISHED);
	assert.deepEqual(strip(skipped.log.entries.find((e) => e["result"] === "SKIPPED")), [
		["src", "harness"],
		["result", "SKIPPED"],
		["msg", "The test was skipped: not supported"],
	]);

	// fireTestSkipped after a failure keeps FAILED
	const failedSkip = await runHarness(async (h) => {
		await h.continueOnFailure(AlwaysFails, ConditionResult.FAILURE);
		h.fireTestSkipped("x");
	});
	assert.equal(failedSkip.m.getResult(), Result.FAILED);

	// review needed does not override FAILED
	const failedReview = await runHarness(async (h) => {
		await h.continueOnFailure(AlwaysFails, ConditionResult.FAILURE);
		h.fireTestReviewNeeded();
	});
	assert.equal(failedReview.m.getResult(), Result.FAILED);

	// a filled placeholder turns UNKNOWN/WARNING into REVIEW at the end
	const review = await runHarness(async (h) => {
		await h.continueOnFailure(AlwaysWarns, ConditionResult.WARNING);
		h.getEventLog().log("x", { msg: "placeholder", upload: "p1" });
		h.getEventLog().entries.at(-1)!["img"] = "data";
	});
	assert.equal(review.m.getResult(), Result.REVIEW);

	// interrupting resets WARNING to UNKNOWN
	const h = new Harness();
	const w = wire(h);
	await h.configure({}, "http://x", "", "");
	await h.setS(Status.RUNNING);
	await h.continueOnFailure(AlwaysWarns, ConditionResult.WARNING);
	assert.equal(h.getResult(), Result.WARNING);
	await h.stop("Stopped by the user.");
	assert.equal(h.getStatus(), Status.INTERRUPTED);
	assert.equal(h.getResult(), Result.UNKNOWN);
	const last = w.log.entries.filter((e) => e.src === "harness").map((e) => e["msg"]);
	assert.deepEqual(last, ["Test was interrupted before it could complete. Stopped by the user.", "Final environment"]);
	assert.ok(w.exec.signal.aborted);
});

test("call(): dispatch of units, commands, skipped conditions and sequences", async () => {
	class Param extends AbstractConditionSequence {
		private readonly v: string;
		constructor(v: string) {
			super();
			this.v = v;
		}
		override evaluate(): void {
			this.call(this.exec().putString("param", this.v));
		}
	}
	class SkipsPutsValue extends AbstractConditionSequence {
		override evaluate(): void {
			this.callAndStopOnFailure(PutsValue);
		}
	}
	let unknown = "";
	let checks = "";
	const { m, log } = await runHarness(async (h) => {
		await h.run(null);
		await h.run(undefined);
		await h.run(
			h
				.cmd()
				.exposeEnvironmentString("s")
				.startBlock("Block A")
				.mapKey("alias", "real")
				.putString("s", "v")
				.putString("o", "p", "w")
				.putInteger("i", 3)
				.endBlock(),
		);
		await h.run(h.seq(() => new Param("from-supplier")));
		const fromSupplier = h.e.getString("param");
		await h.run(h.seq(SkipsPutsValue));
		await h.run(new SkipsPutsValue().skip(PutsValue, "not today"));
		await h.run(h.seqOf(h.cmd().putString("param", "from-sequenceOf")));
		h.e.putString("expose_me", "x");
		await h.run(h.cmd().exposeEnvironmentString("expose_me").removeObject("o").unmapKey("alias"));
		try {
			await h.run({ unitKind: "bogus" } as unknown as TestExecutionUnit);
		} catch (e) {
			unknown = (e as Error).message;
		}
		checks = [fromSupplier, h.e.getString("param"), h.e.getEffectiveKey("alias"), h.e.getObject("o")].join(",");
	});
	assert.equal(unknown, "Unknown class passed to call() function");
	// exposeEnvironmentString runs before the env commands of the same Command
	assert.deepEqual(m.getExposedValues(), { s: null, expose_me: "x" });
	const start = log.entries.find((e) => e.src === "-START-BLOCK-");
	assert.deepEqual(strip(start), [
		["src", "-START-BLOCK-"],
		["msg", "Block A"],
		["startBlock", true],
	]);
	assert.ok(log.entries.some((e) => e.src === "PutsValue" && e["msg"] === "put value"));
	assert.deepEqual(strip(log.entries.find((e) => e["msg"] === "not today")), [
		["src", "PutsValue"],
		["msg", "not today"],
	]);
	assert.equal(m.getStatus(), Status.FINISHED);
	assert.equal(checks, "from-supplier,from-sequenceOf,alias,");
});

test("sequences: default severities of callAndStopOnFailure / callAndContinueOnFailure", async () => {
	class Severities extends AbstractConditionSequence {
		override evaluate(): void {
			this.callAndContinueOnFailure(AlwaysFails); // INFO
			this.callAndContinueOnFailure(AlwaysFails, "R-1"); // WARNING
			this.callAndContinueOnFailure(AlwaysFails, ConditionResult.FAILURE, "R-2");
			this.callAndStopOnFailure(AlwaysWarns, ConditionResult.WARNING, "R-3"); // stops, with WARNING
		}
	}
	const { m, log } = await runHarness(async (h) => {
		await h.run(h.seq(Severities));
	});
	assert.deepEqual(
		log.entries.filter((e) => e.src.startsWith("Always")).map((e) => [e.src, e["result"]]),
		[
			["AlwaysFails", "INFO"],
			["AlwaysFails", "WARNING"],
			["AlwaysFails", "FAILURE"],
			["AlwaysWarns", "WARNING"],
		],
	);
	assert.equal(m.getStatus(), Status.INTERRUPTED);
	assert.equal(m.getResult(), Result.FAILED);
});

test("whenStatus resolves on the first matching status (immediately when already there)", async () => {
	const h = new Harness();
	wire(h);
	assert.equal(await h.whenStatus(Status.CREATED, Status.WAITING), Status.CREATED);
	const waiting = h.whenStatus(Status.WAITING, Status.FINISHED);
	const finished = h.whenStatus(Status.FINISHED, Status.INTERRUPTED);
	await h.configure({}, "http://x", "", "");
	await h.setS(Status.RUNNING);
	await h.setS(Status.WAITING);
	assert.equal(await waiting, Status.WAITING);
	await h.setS(Status.RUNNING);
	await h.stop("bye");
	assert.equal(await finished, Status.INTERRUPTED);
	await h.whenFinished();
});

test("attach exposes the owner to the environment and starts in CREATED", async () => {
	const h = new Harness();
	const log = new TestInstanceEventLog("t9");
	const exec = new TestExecutionManager("t9", { onError: async () => {}, afterTask: () => {} });
	const images = new ImageService(log);
	const browser = new BrowserControl({}, "t9", log, exec, images, () => Promise.reject(new Error("no browser")));
	h.attach({
		id: "t9",
		owner: { sub: "s", iss: "i" },
		eventLog: log,
		browser,
		executionManager: exec,
		imageService: images,
	});
	assert.equal(h.getId(), "t9");
	assert.equal(h.getStatus(), Status.CREATED);
	assert.equal(h.e.getString("owner_id"), "s i");
	assert.equal(h.e.getString("owner_sub"), "s");
	assert.equal(h.e.getString("owner_iss"), "i");
	assert.equal(h.getEventLog(), log);
	assert.equal(h.getTestExecutionManager(), exec);
});
