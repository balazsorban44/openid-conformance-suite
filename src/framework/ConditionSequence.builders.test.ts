import assert from "node:assert/strict";
import { test } from "node:test";
import { AbstractCondition } from "./AbstractCondition.ts";
import { AbstractConditionSequence, sequenceOf } from "./AbstractConditionSequence.ts";
import { ConditionResult, type ConditionClass } from "./Condition.ts";
import { Command } from "./Command.ts";
import { ConditionCallBuilder, type TestExecutionUnit } from "./ConditionCallBuilder.ts";
import { ConditionSequenceCallBuilder, SkippedCondition, type ConditionSequence } from "./ConditionSequence.ts";
import type { Environment } from "./Environment.ts";

class Noop extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		return env;
	}
}
class A extends Noop {}
class B extends Noop {}
class C extends Noop {}
class D extends Noop {}
class X extends Noop {}
class Y extends Noop {}
class Z extends Noop {}
class T extends Noop {}
class Missing extends Noop {}

const classOf = AbstractConditionSequence.actionToConditionClass;
interface Spec {
	onFail: string;
	onSkip: string;
	stopOnFailure: boolean;
	requirements: readonly string[];
}
function specOf(b: ConditionCallBuilder): Spec {
	const { onFail, onSkip, stopOnFailure, requirements } = b.spec;
	return { onFail, onSkip, stopOnFailure, requirements };
}

/** The error getTestExecutionUnits() throws, or "ok" */
function expansionError(s: ConditionSequence): string {
	s.evaluate();
	try {
		s.getTestExecutionUnits();
		return "ok";
	} catch (e) {
		return (e as Error).message;
	}
}
function row(onFail: string, stop: boolean, ...requirements: string[]): Spec {
	return { onFail, onSkip: "INFO", stopOnFailure: stop, requirements };
}

/** A readable rendering of a unit list; nested sequences (insertBefore/After wrappers) are evaluated */
function render(u: TestExecutionUnit): string {
	switch (u.unitKind) {
		case "condition":
			return classOf(u)?.name ?? "?";
		case "skipped":
			return `skip(${(u as SkippedCondition).source}: ${(u as SkippedCondition).message})`;
		case "command":
			return "cmd";
		case "sequence-call":
			return "call:" + render((u as ConditionSequenceCallBuilder).create());
		case "sequence": {
			const s = u as ConditionSequence;
			s.evaluate();
			return "[" + s.getTestExecutionUnits().map(render).join(", ") + "]";
		}
		default:
			return u.unitKind;
	}
}
function units(s: ConditionSequence): string[] {
	s.evaluate();
	return s.getTestExecutionUnits().map(render);
}

class Inner extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(B);
		this.call(this.exec().mapKey("a", "b"));
	}
}
class Inner2 extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndContinueOnFailure(C, ConditionResult.WARNING);
	}
}
class Param extends AbstractConditionSequence {
	readonly v: ConditionClass;
	constructor(v: ConditionClass) {
		super();
		this.v = v;
	}
	override evaluate(): void {
		this.callAndStopOnFailure(this.v);
	}
}
class Outer extends AbstractConditionSequence {
	override evaluate(): void {
		this.call(this.condition(A));
		this.call(this.sequence(Inner));
		this.call(new Inner2());
		this.call([this.condition(D)]);
	}
}

test("sub-sequences (call builders, instances, suppliers) are expanded into a flat list", () => {
	assert.deepEqual(units(new Outer()), ["A", "B", "cmd", "C", "D"]);
	class WithSupplier extends AbstractConditionSequence {
		override evaluate(): void {
			this.call(this.sequence(() => new Param(T)));
			this.call(this.sequenceOf(this.condition(X), this.sequence(Inner)));
		}
	}
	assert.deepEqual(units(new WithSupplier()), ["T", "X", "B", "cmd"]);
	assert.deepEqual(units(sequenceOf(new ConditionCallBuilder(A), new Command())), ["A", "cmd"]);
});

test("replace / skip / insertBefore / insertAfter / then / butFirst", () => {
	const s = new Outer()
		.replace(B, new ConditionCallBuilder(X))
		.skip(C, "no C")
		.insertBefore(A, new ConditionCallBuilder(Y))
		.insertAfter(D, new Command())
		.insertBefore(D, new ConditionCallBuilder(Z))
		.then(new ConditionCallBuilder(T))
		.butFirst(new Command(), new ConditionCallBuilder(B));
	// then/butFirst units are added as they are (not replaced, not expanded); insertBefore wraps first, then
	// insertAfter wraps the result (the nested wrapper flattens when the outer one is expanded)
	assert.deepEqual(units(s), ["cmd", "B", "[Y, A]", "X", "cmd", "skip(C: no C)", "[Z, D, cmd]", "T"]);

	// skip wins over replace (keyed by the original class); insertions wrap the replacement
	const t = new Outer()
		.replace(A, new ConditionCallBuilder(X))
		.skip(A, "no A")
		.replace(D, new ConditionCallBuilder(Z))
		.insertAfter(D, new ConditionCallBuilder(T))
		.butFirst(new ConditionSequenceCallBuilder(Inner2));
	assert.deepEqual(units(t), ["call:[C]", "skip(A: no A)", "B", "cmd", "C", "[Z, T]"]);
});

test("modifications must name a condition of the (expanded) sequence", () => {
	assert.equal(expansionError(new Outer().replace(B, new Command())), "ok"); // B is inside a sub-sequence
	assert.equal(
		expansionError(new Outer().replace(Missing, new Command())),
		"Outer: replacement requested for missing condition: Missing",
	);
	assert.equal(expansionError(new Outer().skip(Missing, "x")), "Outer: skip requested for missing condition: Missing");
	assert.equal(
		expansionError(new Outer().insertBefore(Missing, new Command())),
		"Outer: insertion requested for missing condition: Missing",
	);
	assert.equal(
		expansionError(new Outer().insertAfter(Missing, new Command())),
		"Outer: insertion requested for missing condition: Missing",
	);
	// checked in this order: replacement, skip, insertion
	assert.equal(
		expansionError(new Outer().insertBefore(Missing, new Command()).skip(Missing, "x").replace(Missing, new Command())),
		"Outer: replacement requested for missing condition: Missing",
	);
	assert.equal(
		expansionError(new Outer().insertBefore(Missing, new Command()).skip(Missing, "x")),
		"Outer: skip requested for missing condition: Missing",
	);
	// then/butFirst conditions do not count
	assert.equal(
		expansionError(new Outer().then(new ConditionCallBuilder(Missing)).skip(Missing, "x")),
		"Outer: skip requested for missing condition: Missing",
	);
});

test("default severities of condition(), callAndStopOnFailure() and callAndContinueOnFailure()", () => {
	class Severities extends AbstractConditionSequence {
		override evaluate(): void {
			this.call(this.condition(A));
			this.callAndStopOnFailure(A);
			this.callAndStopOnFailure(A, "R-1", "R-2");
			this.callAndStopOnFailure(A, ConditionResult.WARNING, "R-3");
			this.callAndContinueOnFailure(A);
			this.callAndContinueOnFailure(A, "R-4");
			this.callAndContinueOnFailure(A, ConditionResult.FAILURE, "R-5");
			this.callAndContinueOnFailure(A, ConditionResult.INFO);
		}
	}
	const s = new Severities();
	s.evaluate();
	const specs = s.getTestExecutionUnits().map((u) => specOf(u as ConditionCallBuilder));
	assert.deepEqual(specs, [
		row("FAILURE", true),
		row("FAILURE", true),
		row("FAILURE", true, "R-1", "R-2"),
		row("WARNING", true, "R-3"),
		row("INFO", false),
		row("WARNING", false, "R-4"),
		row("FAILURE", false, "R-5"),
		row("INFO", false),
	]);
});

test("ConditionCallBuilder fluent API", () => {
	const b = new ConditionCallBuilder(A)
		.requirement("R-1")
		.requirements("R-2", ["R-3", "R-4"], null, undefined)
		.onFail(ConditionResult.WARNING)
		.onSkip(ConditionResult.FAILURE)
		.dontStopOnFailure();
	assert.deepEqual(specOf(b), {
		onFail: "WARNING",
		onSkip: "FAILURE",
		stopOnFailure: false,
		requirements: ["R-1", "R-2", "R-3", "R-4"],
	});
	assert.equal(b.unitKind, "condition");
	assert.equal(classOf(b), A);
	const instance = new B();
	assert.equal(classOf(new ConditionCallBuilder(instance)), B);
});

test("actionToConditionClass", () => {
	assert.equal(classOf(new ConditionCallBuilder(C)), C);
	assert.equal(classOf(new Command()), null);
	assert.equal(classOf(new SkippedCondition("C", "x")), null);
	assert.equal(classOf(new ConditionSequenceCallBuilder(Inner)), null);
	assert.equal(classOf(new Inner()), null);
});

test("ConditionSequenceCallBuilder creates a new sequence from a class or a supplier on each create()", () => {
	const fromClass = new ConditionSequenceCallBuilder(Inner);
	assert.equal(fromClass.unitKind, "sequence-call");
	const a = fromClass.create();
	const b = fromClass.create();
	assert.ok(a instanceof Inner);
	assert.notEqual(a, b);
	const fromSupplier = new ConditionSequenceCallBuilder(() => new Param(D));
	const p = fromSupplier.create();
	assert.ok(p instanceof Param);
	assert.equal(p.v, D);
	assert.notEqual(fromSupplier.create(), p);
	// a plain function supplier works too
	const fromFunction = new ConditionSequenceCallBuilder(function () {
		return new Param(X);
	});
	assert.equal((fromFunction.create() as Param).v, X);
});
