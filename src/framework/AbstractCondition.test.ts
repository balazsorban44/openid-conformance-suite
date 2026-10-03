import assert from "node:assert/strict";
import { test } from "node:test";
import { AbstractCondition } from "./AbstractCondition.ts";
import { ConditionError, ConditionResult, type EnvironmentRequirements } from "./Condition.ts";
import { args, ex, type LogArgs } from "./DataUtils.ts";
import { Environment } from "./Environment.ts";
import { TestInstanceEventLog, type LogEntry } from "./EventLog.ts";

/*
 * Pins the log entries and errors AbstractCondition produces today, byte for byte (keys in order).
 */

const UNEXPECTED =
	"Something unexpected happened (this could be caused by something you did wrong, or it may be an issue in the test suite - please review the instructions and your configuration, if you still see a problem please contact certification@oidf.org with the full details)";

/** The entry without the volatile fields the event log adds */
function body(e: LogEntry): LogArgs {
	const { _id, testId: _testId, time: _time, seq: _seq, ...rest } = e;
	return rest;
}

/** The member names in order, comma-separated */
function keys(o: object): string {
	return Object.keys(o).join(",");
}

/** deepEqual plus the same key order (the order is what ends up in log.json) */
function assertEntry(e: LogEntry | undefined, expected: LogArgs): void {
	assert.ok(e, "missing log entry");
	const b = body(e);
	assert.deepEqual(b, expected);
	assert.deepEqual(Object.keys(b), Object.keys(expected));
}

function run<T extends AbstractCondition>(
	c: T,
	onFail: ConditionResult = ConditionResult.FAILURE,
	requirements: string[] = [],
): TestInstanceEventLog {
	const log = new TestInstanceEventLog("tid");
	c.setProperties("tid", log, onFail, requirements);
	return log;
}

async function failsWith(c: AbstractCondition, env: Environment, message: string, prePost = true): Promise<void> {
	await assert.rejects(c.execute(env), (e: unknown) => {
		assert.ok(e instanceof ConditionError);
		assert.equal(e.message, message);
		assert.equal(e.isPreOrPostError, prePost);
		assert.equal(e.testId, "tid");
		return true;
	});
}

class Noop extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.logSuccess("ok");
		return env;
	}
}
class PreObj extends Noop {
	static override pre: EnvironmentRequirements = { required: ["obj"] };
}
class PreStr extends Noop {
	static override pre: EnvironmentRequirements = { strings: ["str"] };
}
class PreInt extends Noop {
	static override pre: EnvironmentRequirements = { integers: ["int"] };
}
class PostObj extends Noop {
	static override post: EnvironmentRequirements = { required: ["obj"] };
}
class PostStr extends Noop {
	static override post: EnvironmentRequirements = { strings: ["str"] };
}
class PostInt extends Noop {
	static override post: EnvironmentRequirements = { integers: ["int"] };
}

for (const [cls, kind, what, key] of [
	[PreObj, "pre", "object", "obj"],
	[PreStr, "pre", "string", "str"],
	[PreInt, "pre", "integer", "int"],
	[PostObj, "post", "object", "obj"],
	[PostStr, "post", "string", "str"],
	[PostInt, "post", "integer", "int"],
] as const) {
	test(`${kind} environment check: missing ${what}`, async () => {
		const c = new cls();
		const log = run(c, ConditionResult.WARNING, ["REQ-1"]);
		const env = new Environment();
		env.mapKey("other", "obj"); // makes "obj" shadowed: "mapped" is then the effective key of "obj" itself
		const when = kind === "pre" ? "before" : "after";
		await failsWith(c, env, `${cls.name}: [${kind}] ${UNEXPECTED} - couldn't find ${what} in environment: ${key}`);
		const expected: LogArgs = {
			src: cls.name,
			msg: `${UNEXPECTED} - couldn't find required ${what} in environment ${when} evaluation: ${key}`,
			expected: key,
			result: "FAILURE",
		};
		if (what === "object") {
			expected["mapped"] = "obj";
		}
		expected["requirements"] = ["REQ-1"];
		assertEntry(log.entries.at(-1), expected);
		assert.equal(log.entries.length, kind === "pre" ? 1 : 2);
	});
}

test("pre object check: mapped is null when the key is not shadowed", async () => {
	const c = new PreObj();
	const log = run(c);
	await failsWith(c, new Environment(), `PreObj: [pre] ${UNEXPECTED} - couldn't find object in environment: obj`);
	assert.equal(log.entries[0]["mapped"], null);
	assert.deepEqual(log.entries[0]["requirements"], []);
});

class Throws extends AbstractCondition {
	fn: (self: Throws) => ConditionError = () => {
		throw new Error("unset");
	};
	override evaluate(_env: Environment): Environment {
		throw this.fn(this);
	}
	call(...a: unknown[]): ConditionError {
		return (this.error as (...x: unknown[]) => ConditionError)(...a);
	}
	reqs(): Set<string> {
		return this.getRequirements();
	}
}

async function errorEntry(
	make: (c: Throws) => ConditionError,
	onFail: ConditionResult = ConditionResult.FAILURE,
	reqs: string[] = [],
): Promise<{ entry: LogEntry; error: ConditionError }> {
	const c = new Throws();
	c.fn = make;
	const log = run(c, onFail, reqs);
	let error: ConditionError | null = null;
	await c.execute(new Environment()).catch((e: ConditionError) => (error = e));
	assert.ok(error);
	assert.equal(log.entries.length, 1);
	return { entry: log.entries[0], error };
}

test("error(message)", async () => {
	const { entry, error } = await errorEntry((c) => c.call("broken"));
	assertEntry(entry, { src: "Throws", msg: "broken", result: "FAILURE" });
	assert.equal(error.message, "Throws: broken");
	assert.equal(error.cause, undefined);
	assert.equal(error.isPreOrPostError, false);
});

test("error(message, map) with onFail WARNING and requirements", async () => {
	const { entry, error } = await errorEntry((c) => c.call("broken", args("k", 1)), ConditionResult.WARNING, ["R-1"]);
	assertEntry(entry, { src: "Throws", k: 1, msg: "broken", result: "WARNING", requirements: ["R-1"] });
	assert.equal(error.message, "Throws: broken");
});

test("error(message, cause) and error(message, cause, map)", async () => {
	const cause = new TypeError("inner");
	let { entry, error } = await errorEntry((c) => c.call("broken", cause));
	assert.equal(keys(body(entry)), "src,error,error_class,result,msg,stacktrace");
	assert.equal(entry["msg"], "broken");
	assert.equal(entry["error"], "inner");
	assert.equal(entry["error_class"], "TypeError");
	assert.equal(error.message, "Throws: broken");
	assert.equal(error.cause, cause);

	({ entry, error } = await errorEntry((c) => c.call("broken", cause, args("k", "v")), ConditionResult.WARNING));
	assert.equal(keys(body(entry)), "src,k,error,error_class,result,msg,stacktrace");
	assert.equal(entry["result"], "WARNING");
	assert.equal(entry["msg"], "broken");
	assert.equal(error.cause, cause);

	// a non-plain-object second argument is a cause too
	({ entry } = await errorEntry((c) => c.call("broken", "string cause")));
	assert.equal(entry["error"], "string cause");
	assert.equal(entry["error_class"], "Error");
});

test("error(cause) and error(cause, map)", async () => {
	const cause = new RangeError("out of range", { cause: new Error("root") });
	let { entry, error } = await errorEntry((c) => c.call(cause));
	assert.equal(keys(body(entry)), "src,error,error_class,cause,cause_class,cause_stacktrace,result,msg,stacktrace");
	assert.equal(entry["msg"], "out of range");
	assert.equal(entry["cause"], "root");
	assert.equal(entry["cause_class"], "Error");
	assert.equal(error.message, "Throws"); // no ": message" suffix
	assert.equal(error.cause, cause);

	({ entry, error } = await errorEntry((c) => c.call(cause, args("x", true))));
	assert.equal(Object.keys(body(entry))[1], "x");
	assert.equal(entry["msg"], "out of range");
	assert.equal(error.message, "Throws");
});

test("ex() shape", () => {
	const plain = ex(new Error("e1"));
	assert.equal(keys(plain), "error,error_class,result,msg,stacktrace");
	assert.equal(plain["msg"], "unexpected exception caught: e1");
	assert.equal(plain["result"], ConditionResult.FAILURE);
	assert.ok(Array.isArray(plain["stacktrace"]) && String((plain["stacktrace"] as string[])[0]).startsWith("at "));

	const withCause = ex(new Error("outer", { cause: new SyntaxError("inner") }), { k: 1 });
	assert.equal(keys(withCause), "k,error,error_class,cause,cause_class,cause_stacktrace,result,msg,stacktrace");
	assert.equal(withCause["cause"], "inner");
	assert.equal(withCause["cause_class"], "SyntaxError");

	const nonErrorCause = ex(new Error("outer", { cause: 42 }), { msg: "given" });
	assert.deepEqual(nonErrorCause, {
		msg: "given",
		error: "outer",
		error_class: "Error",
		cause: "42",
		result: "FAILURE",
	});
	const text = ex("text");
	assert.equal(keys(text), "error,error_class,result,msg,stacktrace");
	assert.equal(text["error"], "text");
	assert.equal(text["error_class"], "Error");
	assert.deepEqual(ex(null, { a: 1 }), { a: 1 });
	assert.deepEqual(ex(undefined), {});
});

class Silent extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		return env;
	}
}

test("Condition ran but did not log anything (no requirements added)", async () => {
	const c = new Silent();
	const log = run(c, ConditionResult.FAILURE, ["R-1"]);
	await c.execute(new Environment());
	assert.equal(log.entries.length, 1);
	assertEntry(log.entries[0], { src: "Silent", msg: "Condition ran but did not log anything" });
});

class LogsFailureWithoutThrowing extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.logFailure("bad", args("k", 1));
		return env;
	}
}

test("logging a failure without throwing is a framework error", async () => {
	const c = new LogsFailureWithoutThrowing();
	const log = run(c, ConditionResult.WARNING);
	await assert.rejects(c.execute(new Environment()), {
		message: "Test condition needs to throw error() if it logs failures/warnings",
	});
	assertEntry(log.entries[0], { src: "LogsFailureWithoutThrowing", k: 1, msg: "bad", result: "WARNING" });
});

class LogsMany extends AbstractCondition {
	count = 0;
	failures = false;
	override evaluate(env: Environment): Environment {
		for (let i = 0; i < this.count; i++) {
			if (this.failures) {
				this.logFailure("failure " + i);
			} else {
				this.log("entry " + i);
			}
		}
		return env;
	}
}

test("logging limits: 50 errors aborts", async () => {
	const c = new LogsMany();
	c.count = 60;
	c.failures = true;
	const log = run(c, ConditionResult.WARNING);
	await assert.rejects(c.execute(new Environment()), {
		message: "LogsMany: This condition has logged over 50 errors and has been aborted.",
	});
	assert.equal(log.entries.length, 51);
	const abort =
		'{"src":"LogsMany","msg":"This condition has logged over 50 errors and has been aborted.","result":"WARNING"}';
	assert.equal(JSON.stringify(body(log.entries[50])), abort);
});

test("logging limits: suppressed after 1000 entries, aborted at 10000", async () => {
	const c = new LogsMany();
	c.count = 1500;
	let log = run(c);
	await c.execute(new Environment());
	assert.equal(log.entries.length, 1000);
	assert.equal(log.entries[998]["msg"], "entry 998");
	const soft =
		'{"src":"LogsMany","msg":"This condition has logged over 1000 log entries. Further entries will be suppressed."}';
	assert.equal(JSON.stringify(body(log.entries[999])), soft);

	const c2 = new LogsMany();
	c2.count = 20000;
	log = run(c2, ConditionResult.INFO);
	await assert.rejects(c2.execute(new Environment()), {
		message: "LogsMany: This condition attempted to log over 10000 log entries and has been aborted.",
	});
	assert.equal(log.entries.length, 1001);
	const hard =
		'{"src":"LogsMany","msg":"This condition attempted to log over 10000 log entries and has been aborted.","result":"INFO"}';
	assert.equal(JSON.stringify(body(log.entries[1000])), hard);
});

class LogVariants extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		this.log("plain");
		this.log("with map", args("a", 1));
		this.log(args("msg", "map only", "requirements", ["OWN"]));
		this.logSuccess("success", args("b", 2));
		this.logSuccess(args("msg", "success map"));
		return env;
	}
}

test("log/logSuccess shapes and requirement injection; getRequirements", async () => {
	const c = new LogVariants();
	const log = run(c, ConditionResult.FAILURE, ["R-1", "R-2", "R-1"]);
	await c.execute(new Environment());
	const reqs = ["R-1", "R-2"];
	assertEntry(log.entries[0], { src: "LogVariants", msg: "plain", requirements: reqs });
	assertEntry(log.entries[1], { src: "LogVariants", a: 1, msg: "with map", requirements: reqs });
	assertEntry(log.entries[2], { src: "LogVariants", msg: "map only", requirements: ["OWN"] });
	assertEntry(log.entries[3], { src: "LogVariants", b: 2, msg: "success", result: "SUCCESS", requirements: reqs });
	assertEntry(log.entries[4], { src: "LogVariants", msg: "success map", result: "SUCCESS", requirements: reqs });

	const t = new Throws();
	run(t, ConditionResult.FAILURE, ["A", "B", "A"]);
	assert.deepEqual(t.reqs(), new Set(["A", "B"]));
	assert.equal(t.getMessage(), "Throws");
});

class ReadsWrongType extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		env.getString("o", "n");
		return env;
	}
}

test("UnexpectedTypeException from the environment becomes error(message, e)", async () => {
	const c = new ReadsWrongType();
	const log = run(c);
	const env = new Environment();
	env.putObject("o", { n: 1 });
	const msg = "If present, a string is expected for o n but JsonPrimitive was found";
	await failsWith(c, env, "ReadsWrongType: " + msg, false);
	assert.equal(log.entries[0]["msg"], msg);
	assert.equal(log.entries[0]["error_class"], "UnexpectedTypeException");
});
