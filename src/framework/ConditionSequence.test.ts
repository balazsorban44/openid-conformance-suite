import assert from "node:assert/strict";
import { test } from "node:test";
import { AbstractCondition } from "./AbstractCondition.ts";
import { AbstractConditionSequence, actionToConditionClass } from "./AbstractConditionSequence.ts";
import { AbstractTestModule } from "./AbstractTestModule.ts";
import { BrowserControl } from "./BrowserControl.ts";
import { ConditionResult } from "./Condition.ts";
import { ConditionCallBuilder, type TestExecutionUnit } from "./ConditionCallBuilder.ts";
import { SkippedCondition, type ConditionSequence } from "./ConditionSequence.ts";
import type { Environment } from "./Environment.ts";
import { TestInstanceEventLog } from "./EventLog.ts";
import { TestExecutionManager } from "./execution.ts";
import { ImageService } from "./ImageService.ts";
import type { PublishTestModule } from "./TestModule.ts";

/*
 * Pins how sequences expand (sub-sequences, replace/skip/insert/then/butFirst) and their default severities.
 */

abstract class Logs extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.log("ran");
		return env;
	}
}
class A extends Logs {}
class B extends Logs {}
class C extends Logs {}
class D extends Logs {}
class E extends Logs {}

class Inner extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(C, "REQ-C");
	}
}

class Outer extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(A);
		this.callAndContinueOnFailure(B);
		this.call(this.sequence(Inner));
	}
}

/** The flattened units as readable names: conditions by class, skips as "skip:<src>:<msg>", sequences in [] */
function names(units: TestExecutionUnit[]): unknown[] {
	return units.map((u) => {
		if (u instanceof SkippedCondition) {
			return `skip:${u.getSource()}:${u.getMessage()}`;
		}
		const c = actionToConditionClass(u);
		if (c != null) {
			return c.name;
		}
		const s = u as ConditionSequence;
		s.evaluate();
		return names(s.getTestExecutionUnits());
	});
}

const d = () => new ConditionCallBuilder(D);

function outer(modify: (s: Outer) => void = () => {}): unknown[] {
	const s = new Outer();
	s.evaluate();
	modify(s);
	return names(s.getTestExecutionUnits());
}

test("sub-sequences are expanded into one flat list", () => {
	assert.deepEqual(outer(), ["A", "B", "C"]);
	class FromSupplier extends AbstractConditionSequence {
		override evaluate(): void {
			this.call(this.sequence(() => new Inner()));
			this.call(new Inner());
			this.call(this.sequenceOf(new ConditionCallBuilder(D)));
		}
	}
	const s = new FromSupplier();
	s.evaluate();
	assert.deepEqual(names(s.getTestExecutionUnits()), ["C", "C", "D"]);
});

test("replace, skip, insertBefore, insertAfter, then, butFirst", () => {
	assert.deepEqual(
		outer((s) => s.replace(B, d())),
		["A", "D", "C"],
	);
	// works on conditions of a sub-sequence
	assert.deepEqual(
		outer((s) => s.replace(C, d())),
		["A", "B", "D"],
	);
	assert.deepEqual(
		outer((s) => s.skip(C, "not needed")),
		["A", "B", "skip:C:not needed"],
	);
	assert.deepEqual(
		outer((s) => s.insertBefore(B, d())),
		["A", ["D", "B"], "C"],
	);
	assert.deepEqual(
		outer((s) => s.insertAfter(B, d())),
		["A", ["B", "D"], "C"],
	);
	assert.deepEqual(
		outer((s) => s.then(d(), new ConditionCallBuilder(E)).butFirst(new ConditionCallBuilder(E))),
		["E", "A", "B", "C", "D", "E"],
	);
	// precedence: replace, then skip (by the original class), then insertBefore, then insertAfter
	assert.deepEqual(
		outer((s) => s.replace(B, d()).skip(B, "m").insertBefore(B, new ConditionCallBuilder(E)).insertAfter(B, d())),
		["A", ["E", "skip:B:m", "D"], "C"], // the nested insertBefore sequence is flattened by the insertAfter one
	);
	// the replacement is not looked up again
	assert.deepEqual(
		outer((s) => s.replace(A, new ConditionCallBuilder(B)).replace(B, d())),
		["B", "D", "C"],
	);
});

test("modifying a condition that is not in the sequence throws", () => {
	for (const [modify, what] of [
		[(s: Outer) => s.replace(D, d()), "replacement"],
		[(s: Outer) => s.skip(D, "x"), "skip"],
		[(s: Outer) => s.insertBefore(D, d()), "insertion"],
		[(s: Outer) => s.insertAfter(D, d()), "insertion"],
	] as const) {
		assert.throws(() => outer(modify), { message: `Outer: ${what} requested for missing condition: D` });
	}
});

test("default severities of sequence calls", () => {
	class Severities extends AbstractConditionSequence {
		override evaluate(): void {
			this.callAndStopOnFailure(A);
			this.callAndStopOnFailure(A, "R-1");
			this.callAndStopOnFailure(A, ConditionResult.WARNING, "R-1");
			this.callAndContinueOnFailure(B);
			this.callAndContinueOnFailure(B, "R-1", "R-2");
			this.callAndContinueOnFailure(B, ConditionResult.FAILURE);
		}
	}
	const s = new Severities();
	s.evaluate();
	const got = (s.getTestExecutionUnits() as ConditionCallBuilder[]).map((b) => [
		b.getConditionClass().name,
		b.getOnFail(),
		b.isStopOnFailure(),
		b.getRequirements(),
		b.getOnSkip(),
	]);
	assert.deepEqual(got, [
		["A", "FAILURE", true, [], "INFO"],
		["A", "FAILURE", true, ["R-1"], "INFO"],
		["A", "WARNING", true, ["R-1"], "INFO"],
		["B", "INFO", false, [], "INFO"],
		["B", "WARNING", false, ["R-1", "R-2"], "INFO"],
		["B", "FAILURE", false, [], "INFO"],
	]);
});

class SeqModule extends AbstractTestModule {
	static override readonly meta: PublishTestModule = { testName: "seq-module", displayName: "x", profile: "x" };
	override async configure(): Promise<void> {}
	override async start(): Promise<void> {}
	runSequence(s: ConditionSequence): Promise<void> {
		return this.call(s);
	}
}

test("a skipped condition logs only its message under the condition's name", async () => {
	const log = new TestInstanceEventLog("tid");
	const m = new SeqModule();
	const exec = new TestExecutionManager("tid", { onError: async () => {}, afterTask: () => {} });
	const images = new ImageService(log);
	m.setProperties(
		"tid",
		null,
		log,
		new BrowserControl({}, "tid", log, exec, images, () => Promise.reject()),
		exec,
		images,
	);
	const s = new Outer();
	s.skip(B, "B is not applicable");
	await m.runSequence(s);
	const out = log.entries.map(({ _id, testId: _testId, time: _time, seq: _seq, ...rest }) => rest);
	assert.deepEqual(out, [
		{ src: "A", msg: "ran" },
		{ src: "B", msg: "B is not applicable" },
		{ src: "C", msg: "ran", requirements: ["REQ-C"] },
	]);
});
