import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { block, condition, ConditionFailed, skipped, soft, type Condition } from "./conditions.ts";
import { createLog, resultOf, useLog, type EventLog } from "./log.ts";

let log: EventLog;
let uninstall: () => void;

beforeEach(() => {
	log = createLog("t1");
	uninstall = useLog(log, { testName: "oidcc-test" });
});
afterEach(() => uninstall());

/** The entries without the per-run fields */
function entries() {
	return log.entries.map(({ _id: _, testId: _t, time: _time, seq: _seq, ...rest }) => rest);
}

function check(ok: boolean): void {
	const c: Condition = condition("CheckSomething", "SPEC-1");
	if (!ok) {
		c.failure("Something is wrong", { actual: 1 });
	}
	c.success("Something is right");
}

describe("condition", () => {
	test("records upstream-shaped entries under the condition name, with the requirements", () => {
		check(true);
		condition("Plain").log("no result", { k: "v" });
		condition("Fields").log({ only: "fields" });
		expect(entries()).toEqual([
			{ src: "CheckSomething", msg: "Something is right", result: "SUCCESS", requirements: ["SPEC-1"] },
			{ src: "Plain", msg: "no result", k: "v" },
			{ src: "Fields", only: "fields" },
		]);
	});

	test("failure() records a FAILURE and throws ConditionFailed (callAndStopOnFailure)", () => {
		expect(() => check(false)).toThrow(new ConditionFailed("CheckSomething", "Something is wrong", "FAILURE"));
		expect(entries()).toEqual([
			{ src: "CheckSomething", msg: "Something is wrong", actual: 1, result: "FAILURE", requirements: ["SPEC-1"] },
		]);
	});

	test("failureFrom() adds the exception fields", () => {
		expect(() => condition("C").failureFrom("Broken", new TypeError("bad", { cause: new Error("root") }))).toThrow(
			ConditionFailed,
		);
		expect(entries()[0]).toMatchObject({ error: "bad", error_class: "TypeError", cause: "root", result: "FAILURE" });
	});
});

describe("soft", () => {
	test("continues after a failure (callAndContinueOnFailure) and returns undefined", () => {
		expect(soft(() => check(false))).toBeUndefined();
		expect(soft(() => 42)).toBe(42);
		expect(entries().map((e) => e["result"])).toEqual(["FAILURE"]);
	});

	test("records the failure with the given severity", async () => {
		soft(() => check(false), "warning");
		soft(() => check(false), "info");
		await soft(async () => {
			await Promise.resolve();
			check(false);
		}, "warning");
		expect(entries().map((e) => e["result"])).toEqual(["WARNING", "INFO", "WARNING"]);
	});

	test("does not swallow other errors", () => {
		expect(() =>
			soft(() => {
				throw new Error("bug");
			}),
		).toThrow("bug");
	});
});

describe("block / skipped / resultOf", () => {
	test("entries inside a block carry its id, the block is closed afterwards", async () => {
		await block("Do things", () => check(true));
		check(true);
		const [start, inside, after] = log.entries;
		expect(start).toMatchObject({ src: "-START-BLOCK-", msg: "Do things", startBlock: true });
		expect(inside["blockId"]).toBe(start["blockId"]);
		expect(after["blockId"]).toBeUndefined();
	});

	test("skipped() logs upstream's skip entry", () => {
		skipped("ValidateAtHash", { object: "at_hash" }, "OIDCC-3.3.2.11");
		skipped("ValidateEncryptedIdTokenHasKid", { element: ["id_token", "jwe_header"] });
		expect(entries()).toEqual([
			{
				src: "ValidateAtHash",
				msg: "Skipped evaluation due to missing required object: at_hash",
				expected: "at_hash",
				result: "INFO",
				requirements: ["OIDCC-3.3.2.11"],
			},
			{
				src: "ValidateEncryptedIdTokenHasKid",
				msg: "Skipped evaluation due to missing required element: id_token jwe_header",
				object: "id_token",
				path: "jwe_header",
				result: "INFO",
				requirements: [],
			},
		]);
	});

	test("resultOf: FAILED > SKIPPED > WARNING > REVIEW > PASSED", () => {
		soft(() => check(false), "warning");
		expect(resultOf(log.entries)).toBe("WARNING");
		condition("Review").review("look at this", { upload: "p1" });
		expect(resultOf(log.entries)).toBe("WARNING");
		log.fillPlaceholder("p1", { image_no_longer_required: true });
		soft(() => check(false));
		expect(resultOf(log.entries)).toBe("FAILED");
		expect(resultOf([])).toBe("PASSED");
		expect(resultOf([], true)).toBe("SKIPPED");
	});
});

test("checks need a running test", () => {
	uninstall();
	expect(() => condition("X")).toThrow(/No conformance test is running/);
	uninstall = useLog(log);
});
