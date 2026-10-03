import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { BrowserHook } from "../framework/BrowserControl.ts";
import { isJsonObject, type JsonObject } from "../framework/json.ts";

/**
 * A test configuration: the upstream JSON format (server, client, client2, browser, alias, ...) plus a few
 * runner-only keys:
 *
 *   target          - an implementation under test to start before the plan (see target.ts)
 *   client_driver   - how to kick off the RP under test for RP plans (see TestRunner.driveClient)
 *   expectedFailures / expectedSkips - paths to upstream-format expected-failure/skip lists
 *   browser         - the upstream JSON automation array, or (in a .ts config) a BrowserHook function
 */
export interface TargetConfig {
	command: string;
	readyUrl: string;
	cwd?: string;
	env?: Record<string, string>;
	/** seconds to wait for readyUrl (default 60) */
	timeoutSeconds?: number;
}

export interface ClientDriverConfig {
	startUrl: string;
	/** extra query parameters for every start call */
	params?: Record<string, string>;
	/** seconds to wait for the RP to finish a module (default 120) */
	timeoutSeconds?: number;
}

export type ConformanceConfig = JsonObject;

/**
 * suite-vs-suite: run an RP test module of this suite as the emulated OP that the OP plan under test talks to.
 * The emulated module is started fresh for every OP module and its base URL is injected as server.discoveryUrl.
 */
export interface SuiteTargetConfig {
	/** testName of the RP module acting as OP, e.g. "oidcc-client-test" */
	module: string;
	variant?: Record<string, string>;
	alias?: string;
	/** configuration handed to the emulated module (client, client2, ...) */
	config?: JsonObject;
}

export interface LoadedConfig {
	suiteTarget: SuiteTargetConfig | null;
	/** The JSON handed to the test module (runner-only keys removed) */
	config: ConformanceConfig;
	/** The browser hook when the config is a .ts/.js module exporting one */
	browserHook: BrowserHook | null;
	target: TargetConfig | null;
	clientDriver: ClientDriverConfig | null;
	expectedFailures: ExpectedFailure[];
	expectedSkips: ExpectedSkip[];
	/** Absolute path of the config file */
	path: string;
	/** File name of the config (used for `configuration-filename` matching in expected-failure lists) */
	filename: string;
}

/** Upstream `.gitlab-ci/expected-failures-*.json` entry */
export interface ExpectedFailure {
	"test-name": string;
	variant: "*" | Record<string, string>;
	"configuration-filename": string;
	"current-block": string;
	condition: string;
	"expected-result": "failure" | "warning";
	comment?: string;
}

/** Upstream `.gitlab-ci/expected-skips-*.json` entry */
export interface ExpectedSkip {
	"test-name": string;
	variant: "*" | Record<string, string>;
	"configuration-filename": string;
	comment?: string;
}

const RUNNER_KEYS = ["target", "client_driver", "expectedFailures", "expectedSkips", "suite_target"] as const;

export async function loadConfig(path: string): Promise<LoadedConfig> {
	const abs = resolve(path);
	let raw: Record<string, unknown>;
	if (abs.endsWith(".json")) {
		raw = JSON.parse(await readFile(abs, "utf8")) as Record<string, unknown>;
	} else {
		const mod = (await import(pathToFileURL(abs).href)) as { default?: unknown; config?: unknown };
		const exported = mod.default ?? mod.config;
		if (!exported || typeof exported !== "object") {
			throw new Error(`Config module ${abs} must default-export the configuration object`);
		}
		raw = exported as Record<string, unknown>;
	}
	const target = (raw["target"] as TargetConfig | undefined) ?? null;
	const clientDriver = (raw["client_driver"] as ClientDriverConfig | undefined) ?? null;
	const suiteTarget = (raw["suite_target"] as SuiteTargetConfig | undefined) ?? null;
	const expectedFailures = await loadList<ExpectedFailure>(raw["expectedFailures"], abs);
	const expectedSkips = await loadList<ExpectedSkip>(raw["expectedSkips"], abs);

	let browserHook: BrowserHook | null = null;
	const config: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(raw)) {
		if ((RUNNER_KEYS as readonly string[]).includes(k)) {
			continue;
		}
		if (k === "browser" && typeof v === "function") {
			browserHook = v as BrowserHook;
			continue;
		}
		config[k] = v;
	}
	if (!isJsonObject(config)) {
		throw new Error("Configuration must be a JSON object");
	}
	return {
		config: config as ConformanceConfig,
		browserHook,
		target,
		clientDriver,
		suiteTarget,
		expectedFailures,
		expectedSkips,
		path: abs,
		filename: basename(abs),
	};
}

async function loadList<T>(ref: unknown, configPath: string): Promise<T[]> {
	if (ref == null) {
		return [];
	}
	if (Array.isArray(ref)) {
		return ref as T[];
	}
	if (typeof ref === "string") {
		const p = resolve(configPath, "..", ref);
		return JSON.parse(await readFile(p, "utf8")) as T[];
	}
	throw new Error("expectedFailures/expectedSkips must be an array or a path");
}
