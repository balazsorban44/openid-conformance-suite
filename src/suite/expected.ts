import { fnmatch, type ExpectedFailure, type ExpectedSkip } from "./config.ts";
import type { LogEntry } from "./log.ts";

export interface ConditionRef {
	current_block: string;
	src: string;
	msg?: string;
}

export interface ModuleAnalysis {
	expected_failures: ConditionRef[];
	unexpected_failures: ConditionRef[];
	expected_failures_did_not_happen: ConditionRef[];
	expected_warnings: ConditionRef[];
	unexpected_warnings: ConditionRef[];
	expected_warnings_did_not_happen: ConditionRef[];
	expected_skip: boolean;
	unexpected_skip: boolean;
	expected_skip_did_not_happen: boolean;
	counts: { SUCCESS: number; WARNING: number; FAILURE: number };
	/** True when nothing unexpected happened (the Playwright test passes) */
	ok: boolean;
}

/** An analysis of nothing (e.g. a test that crashed before its module ran); `ok` is false */
export function emptyAnalysis(): ModuleAnalysis {
	return {
		expected_failures: [],
		unexpected_failures: [],
		expected_failures_did_not_happen: [],
		expected_warnings: [],
		unexpected_warnings: [],
		expected_warnings_did_not_happen: [],
		expected_skip: false,
		unexpected_skip: false,
		expected_skip_did_not_happen: false,
		counts: { SUCCESS: 0, WARNING: 0, FAILURE: 0 },
		ok: false,
	};
}

function isExpectedForThisTest(
	obj: ExpectedFailure | ExpectedSkip,
	testName: string,
	variant: Record<string, string>,
	configFilename: string,
): boolean {
	if (!fnmatch(obj["test-name"], testName)) {
		return false;
	}
	if (obj["configuration-filename"] && !fnmatch(obj["configuration-filename"], configFilename)) {
		return false;
	}
	const expectedVariant = obj.variant;
	if (expectedVariant === "*" || expectedVariant == null) {
		return true;
	}
	return Object.entries(expectedVariant).every(([k, v]) => k in variant && variant[k] === v);
}

/**
 * Port of analyze_result_logs() from upstream scripts/run-test-plan.py: compare a module's log against the
 * expected-failure / expected-skip lists.
 */
export function analyzeResultLogs(
	testName: string,
	variant: Record<string, string>,
	testResult: string,
	logs: LogEntry[],
	expectedFailuresList: ExpectedFailure[],
	expectedSkipsList: ExpectedSkip[],
	configFilename: string,
): ModuleAnalysis {
	const out = emptyAnalysis();
	const isForThisTest = (o: ExpectedFailure | ExpectedSkip) =>
		isExpectedForThisTest(o, testName, variant, configFilename);
	const testExpectedFailures = expectedFailuresList.filter(isForThisTest);
	const testExpectedSkips = expectedSkipsList.filter(isForThisTest);
	const used = new Set<ExpectedFailure>();

	const blockNames = new Map<string, string>();
	for (const entry of logs) {
		if (entry["startBlock"] === true && entry.src === "-START-BLOCK-") {
			blockNames.set(String(entry["blockId"]), String(entry["msg"]));
			continue;
		}
		if (entry["result"] == null) {
			continue;
		}
		const logResult = String(entry["result"]);
		if (!(logResult in out.counts)) {
			continue;
		}
		out.counts[logResult as keyof ModuleAnalysis["counts"]]++;
		const blockMsg = entry["blockId"] != null ? (blockNames.get(String(entry["blockId"])) ?? "") : "";
		const ref: ConditionRef = { current_block: blockMsg, src: entry.src, msg: msgOf(entry) };
		// SUCCESS never matches: expected-result is "failure" or "warning"
		const expected = testExpectedFailures.find(
			(e) =>
				(e["current-block"] === blockMsg || e["current-block"] === "*") &&
				e.condition === entry.src &&
				e["expected-result"] === logResult.toLowerCase(),
		);
		if (expected) {
			used.add(expected);
			(logResult === "FAILURE" ? out.expected_failures : out.expected_warnings).push(ref);
		} else if (logResult === "FAILURE") {
			out.unexpected_failures.push(ref);
		} else if (logResult === "WARNING") {
			out.unexpected_warnings.push(ref);
		}
	}

	for (const expected of testExpectedFailures) {
		if (used.has(expected)) {
			continue;
		}
		const ref = { current_block: expected["current-block"], src: expected.condition };
		if (expected["expected-result"] === "failure") {
			out.expected_failures_did_not_happen.push(ref);
		} else if (expected["expected-result"] === "warning") {
			out.expected_warnings_did_not_happen.push(ref);
		}
	}

	if (testExpectedSkips.length > 0) {
		if (testResult === "SKIPPED" || testResult === "FAILED") {
			out.expected_skip = true;
		} else {
			out.expected_skip_did_not_happen = true;
		}
	}
	if (testResult === "SKIPPED" && !out.expected_skip) {
		out.unexpected_skip = true;
	}

	const knownResult = ["PASSED", "WARNING", "REVIEW", "SKIPPED", "FAILED"].includes(String(testResult));
	out.ok = knownResult && describeProblems(out).length === 0;
	return out;
}

/** Everything noteworthy in an analysis, in report order */
export type Finding =
	| {
			kind:
				| "unexpected failure"
				| "unexpected warning"
				| "expected failure"
				| "expected warning"
				| "expected failure did not happen"
				| "expected warning did not happen";
			ref: ConditionRef;
	  }
	| { kind: "unexpected skip" | "expected skip did not happen" };

export function findings(a: ModuleAnalysis): Finding[] {
	const refs = (kind: Extract<Finding, { ref: ConditionRef }>["kind"], list: ConditionRef[]): Finding[] =>
		list.map((ref) => ({ kind, ref }));
	return [
		...refs("unexpected failure", a.unexpected_failures),
		...refs("unexpected warning", a.unexpected_warnings),
		...refs("expected failure", a.expected_failures),
		...refs("expected warning", a.expected_warnings),
		...refs("expected failure did not happen", a.expected_failures_did_not_happen),
		...refs("expected warning did not happen", a.expected_warnings_did_not_happen),
		...(a.unexpected_skip ? [{ kind: "unexpected skip" } as const] : []),
		...(a.expected_skip_did_not_happen ? [{ kind: "expected skip did not happen" } as const] : []),
	];
}

/** The findings that make a module fail (expected failures/warnings are not problems), one line each */
export function describeProblems(a: ModuleAnalysis): string[] {
	return findings(a).flatMap((f): string[] => {
		switch (f.kind) {
			case "unexpected failure":
				return [`FAILURE ${f.ref.src}${f.ref.current_block ? ` [${f.ref.current_block}]` : ""}: ${f.ref.msg ?? ""}`];
			case "unexpected warning":
				return [`WARNING ${f.ref.src}: ${f.ref.msg ?? ""}`];
			case "expected failure did not happen":
			case "expected warning did not happen":
				return [`${f.kind}: ${f.ref.src}`];
			case "unexpected skip":
				return ["module was unexpectedly SKIPPED"];
			case "expected skip did not happen":
				return ["module was expected to be skipped but completed"];
			case "expected failure":
			case "expected warning":
				return [];
		}
	});
}

function msgOf(entry: LogEntry): string | undefined {
	const m = entry["msg"];
	return typeof m === "string" ? m : undefined;
}
