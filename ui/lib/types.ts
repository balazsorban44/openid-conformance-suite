/**
 * The data the pages and the API share. Client-safe: no node imports. The report shapes are the suite's own
 * (src/suite/report.ts ModuleReport, src/suite/expected.ts ModuleAnalysis, src/suite/log.ts LogEntry).
 */
import type { ConformanceProject, Plan } from "../../src/runner/projects.ts";
import type { ConditionRef, ModuleAnalysis } from "../../src/suite/expected.ts";
import type { LogEntry } from "../../src/suite/log.ts";
import type { ModuleReport } from "../../src/suite/report.ts";

export type { ConditionRef, ConformanceProject, LogEntry, ModuleAnalysis, ModuleReport, Plan };

/** A module report with where its files are */
export interface ModuleRecord {
	report: ModuleReport;
	/** Directory with log.json, log.html, screenshots, relative to the results directory; null when only results.json has it */
	dir: string | null;
	/** When the module finished (module-report.json's mtime), epoch ms; 0 when unknown (only in results.json) */
	finishedAt: number;
}

/** What the UI shows for a module: its report's result and whether the configuration expected it */
export type Outcome =
	| "passed"
	| "warning"
	| "review"
	| "skipped"
	| "expected-failure"
	| "failed"
	| "interrupted"
	| "not-run"
	| "pending"
	| "running"
	| "cancelled";

export interface ModuleStatus {
	name: string;
	/** the module list (nested describe) of a plan that runs the module once per list, e.g. "response_type=id_token" */
	moduleList?: string;
	record: ModuleRecord | null;
	/** the project does not run this module (skipModules), and why */
	skipReason?: string;
}

/** A module of the overview strip (components/module-strip.tsx) */
export interface StripModule {
	name: string;
	outcome: Outcome;
	/** the module's log, when it has one */
	testId?: string;
	/** shown instead of the outcome (a module the project does not run) */
	note?: string;
}

export interface ProjectStatus {
	project: ConformanceProject;
	kind: "OP" | "RP";
	modules: ModuleStatus[];
	counts: Record<"ok" | "failed" | "notRun", number>;
	lastRunAt: number | null;
}

export interface PlanInfo extends Plan {
	name: string;
	kind: "OP" | "RP";
	/** the CI projects running this plan */
	projects: string[];
}

/** What starts a run: a CI project, or a plan with a configuration and variant (bin/cli.ts `ci` / `run`) */
export type RunRequest =
	| { kind: "project"; project: string; module?: string; options?: RunOptions }
	| {
			kind: "plan";
			plan: string;
			config: string;
			variant: Record<string, string>;
			module?: string;
			tls?: boolean;
			options?: RunOptions;
	  };

export interface RunOptions {
	/** CONFORMANCE_VERBOSE: stream every log entry to the console */
	verbose?: boolean;
	/** keep Playwright's video of failing modules (CONFORMANCE_VIDEO) */
	video?: boolean;
	/** keep Playwright's trace of failing modules (CONFORMANCE_TRACE) */
	trace?: boolean;
}

export type RunStatus = "starting" | "running" | "passed" | "failed" | "cancelled" | "error";

export interface RunModule {
	/** Playwright test title: "<module>: <what the OP/RP must do>" */
	title: string;
	name: string;
	state: "pending" | "running" | "done";
	outcome: Outcome;
	durationMs?: number;
	testId?: string;
}

export interface RunInfo {
	id: string;
	label: string;
	request: RunRequest;
	plan: string;
	variant: string;
	command: string;
	/** the run's Playwright output directory, relative to the results directory */
	outputDir: string;
	status: RunStatus;
	startedAt: number;
	endedAt?: number;
	exitCode?: number | null;
	error?: string;
	modules: RunModule[];
}

/** Server-Sent Events of a run (`/api/runs/<id>/events`) */
export type RunEvent =
	| { type: "snapshot"; run: RunInfo; output: string[] }
	| { type: "output"; lines: string[] }
	| { type: "module"; index: number; module: RunModule }
	| { type: "modules"; modules: RunModule[] }
	| { type: "status"; run: RunInfo };
