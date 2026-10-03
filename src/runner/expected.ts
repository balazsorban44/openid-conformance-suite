import type { LogEntry } from "../framework/EventLog.ts";
import type { Result } from "../framework/TestModule.ts";
import type { ExpectedFailure, ExpectedSkip } from "./config.ts";

/**
 * Port of analyze_result_logs() from upstream scripts/run-test-plan.py: compare a module's log against the
 * expected-failure / expected-skip lists.
 */
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

/** fnmatch-style glob (`*`, `?`) */
export function fnmatch(pattern: string, s: string): boolean {
	const re = new RegExp(
		"^" +
			pattern
				.split("")
				.map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\]/g, "\\$&")))
				.join("") +
			"$",
	);
	return re.test(s);
}

function isExpectedForThisTest(
	obj: { "test-name": string; variant: "*" | Record<string, string>; "configuration-filename"?: string },
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
	for (const k of Object.keys(expectedVariant)) {
		if (!(k in variant)) {
			return false;
		}
		if (expectedVariant[k] !== variant[k]) {
			return false;
		}
	}
	return true;
}

export function analyzeResultLogs(
	testName: string,
	variant: Record<string, string>,
	testResult: Result | string,
	logs: LogEntry[],
	expectedFailuresList: ExpectedFailure[],
	expectedSkipsList: ExpectedSkip[],
	configFilename: string,
): ModuleAnalysis {
	const counts = { SUCCESS: 0, WARNING: 0, FAILURE: 0 };
	const out: ModuleAnalysis = {
		expected_failures: [],
		unexpected_failures: [],
		expected_failures_did_not_happen: [],
		expected_warnings: [],
		unexpected_warnings: [],
		expected_warnings_did_not_happen: [],
		expected_skip: false,
		unexpected_skip: false,
		expected_skip_did_not_happen: false,
		counts,
		ok: true,
	};

	const testExpectedFailures = expectedFailuresList.filter((o) => isExpectedForThisTest(o, testName, variant, configFilename));
	const testExpectedSkips = expectedSkipsList.filter((o) => isExpectedForThisTest(o, testName, variant, configFilename));
	const used = new Set<ExpectedFailure>();

	const blockNames = new Map<string, string>();
	let blockMsg = "";
	for (const entry of logs) {
		if (entry["startBlock"] === true && entry.src === "-START-BLOCK-") {
			blockNames.set(String(entry["blockId"]), String(entry["msg"]));
			continue;
		}
		if (!("result" in entry) || entry["result"] == null) {
			continue;
		}
		if (entry["blockId"] != null) {
			blockMsg = blockNames.get(String(entry["blockId"])) ?? "";
		} else {
			blockMsg = "";
		}
		const logResult = String(entry["result"]);
		if (!(logResult in counts)) {
			continue;
		}
		counts[logResult as keyof typeof counts]++;
		let existsInExpectedList = false;
		for (const expected of testExpectedFailures) {
			const expectedBlock = expected["current-block"];
			if ((expectedBlock === blockMsg || expectedBlock === "*") && expected.condition === entry.src) {
				if (logResult === "FAILURE" && expected["expected-result"] === "failure") {
					out.expected_failures.push({ current_block: blockMsg, src: entry.src, msg: msgOf(entry) });
				} else if (logResult === "WARNING" && expected["expected-result"] === "warning") {
					out.expected_warnings.push({ current_block: blockMsg, src: entry.src, msg: msgOf(entry) });
				} else {
					continue;
				}
				existsInExpectedList = true;
				used.add(expected);
				break;
			}
		}
		if (!existsInExpectedList) {
			if (logResult === "FAILURE") {
				out.unexpected_failures.push({ current_block: blockMsg, src: entry.src, msg: msgOf(entry) });
			}
			if (logResult === "WARNING") {
				out.unexpected_warnings.push({ current_block: blockMsg, src: entry.src, msg: msgOf(entry) });
			}
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

	for (const _skip of testExpectedSkips) {
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
	out.ok =
		knownResult &&
		out.unexpected_failures.length === 0 &&
		out.unexpected_warnings.length === 0 &&
		!out.unexpected_skip &&
		out.expected_failures_did_not_happen.length === 0 &&
		out.expected_warnings_did_not_happen.length === 0 &&
		!out.expected_skip_did_not_happen;
	return out;
}

function msgOf(entry: LogEntry): string | undefined {
	const m = entry["msg"];
	return typeof m === "string" ? m : undefined;
}
