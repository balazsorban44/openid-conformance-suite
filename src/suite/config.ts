/**
 * Test configurations: upstream's JSON format (server, client, client2, browser, alias, override, ...) plus the
 * runner keys this port adds, as a .json file or a .ts module default-exporting the object:
 *
 *   target           the implementation under test to start (see target.ts); its `url` (with `${PORT}`, a free
 *                    port) is substituted for `${TARGET_URL}` everywhere in the configuration
 *   client_driver    how to kick off the RP under test for RP plans
 *   suite_target     suite-vs-suite: an RP module of this suite acting as the OP under test
 *   expectedFailures / expectedSkips   upstream-format lists (or paths to them, relative to the config file)
 *   browser          upstream's JSON automation, or (in a .ts config) a BrowserHook function
 *   override         { "<test name>": { ...top-level keys replaced for that module } } (upstream DBTestPlanService)
 */
import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { BrowserAutomation } from "./browser.ts";

export interface TargetConfig {
	command: string;
	/** The target's base URL; `${PORT}` is replaced with a free port that the command receives as PORT */
	url?: string;
	readyUrl: string;
	cwd?: string;
	env?: Record<string, string>;
	/** seconds to wait for readyUrl (default 60) */
	timeoutSeconds?: number;
}

export interface ClientDriverConfig {
	startUrl: string;
	params?: Record<string, string>;
	timeoutSeconds?: number;
}

export interface SuiteTargetConfig {
	module: string;
	variant?: Record<string, string>;
	alias?: string;
	config?: Record<string, unknown>;
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

/** The configuration a test module sees (runner keys removed, `browser` may be a hook) */
export type TestConfig = Record<string, unknown> & {
	alias?: string;
	server?: Record<string, unknown>;
	client?: Record<string, unknown>;
	client2?: Record<string, unknown>;
	browser?: BrowserAutomation;
	browser_verbose?: boolean;
};

export interface LoadedConfig {
	config: TestConfig;
	target: TargetConfig | null;
	clientDriver: ClientDriverConfig | null;
	suiteTarget: SuiteTargetConfig | null;
	expectedFailures: ExpectedFailure[];
	expectedSkips: ExpectedSkip[];
	/** Absolute path of the config file */
	path: string;
	/** File name, matched against `configuration-filename` in the expected lists */
	filename: string;
}

const RUNNER_KEYS = ["target", "client_driver", "expectedFailures", "expectedSkips", "suite_target"];

/** Reads a .json config or imports a .ts/.js config module (its default export) */
export async function readConfig(path: string): Promise<Record<string, unknown>> {
	const abs = resolve(path);
	if (abs.endsWith(".json")) {
		return JSON.parse(await readFile(abs, "utf8")) as Record<string, unknown>;
	}
	const mod = (await import(pathToFileURL(abs).href)) as { default?: unknown; config?: unknown };
	const exported = mod.default ?? mod.config;
	if (!exported || typeof exported !== "object") {
		throw new Error(`Config module ${abs} must default-export the configuration object`);
	}
	return exported as Record<string, unknown>;
}

/** Replaces `${NAME}` in every string of `value` (functions and other values are kept as they are) */
export function substitute<T>(value: T, vars: Record<string, string>): T {
	if (typeof value === "string") {
		return value.replace(/\$\{(\w+)\}/g, (m, name: string) => vars[name] ?? m) as T;
	}
	if (Array.isArray(value)) {
		return value.map((v) => substitute(v, vars)) as T;
	}
	if (value != null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
		return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitute(v, vars)])) as T;
	}
	return value;
}

/**
 * Splits the runner keys off a raw configuration and resolves `${TARGET_URL}` (`vars`) everywhere.
 * `path` is the config file (expected-failure list paths are relative to it).
 */
export async function loadConfig(
	path: string,
	raw?: Record<string, unknown>,
	vars: Record<string, string> = {},
): Promise<LoadedConfig> {
	const abs = resolve(path);
	const resolved = substitute(raw ?? (await readConfig(abs)), vars);
	const config: TestConfig = {};
	for (const [k, v] of Object.entries(resolved)) {
		if (!RUNNER_KEYS.includes(k)) {
			config[k] = v;
		}
	}
	return {
		config,
		target: (resolved["target"] as TargetConfig | undefined) ?? null,
		clientDriver: (resolved["client_driver"] as ClientDriverConfig | undefined) ?? null,
		suiteTarget: (resolved["suite_target"] as SuiteTargetConfig | undefined) ?? null,
		expectedFailures: await loadList<ExpectedFailure>(resolved["expectedFailures"], abs),
		expectedSkips: await loadList<ExpectedSkip>(resolved["expectedSkips"], abs),
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
		return JSON.parse(await readFile(resolve(configPath, "..", ref), "utf8")) as T[];
	}
	throw new Error("expectedFailures/expectedSkips must be an array or a path");
}

/**
 * The configuration for one test module (upstream DBTestPlanService.getModuleConfig): the keys under
 * `override["<testName>"]` replace the top-level keys, and `override` itself is removed.
 */
export function moduleConfig(config: TestConfig, testName: string): TestConfig {
	const { override, ...rest } = config;
	const out: TestConfig = structuredCloneConfig(rest);
	if (override != null && typeof override === "object" && !Array.isArray(override)) {
		const forModule = (override as Record<string, unknown>)[testName];
		if (forModule != null && typeof forModule === "object" && !Array.isArray(forModule)) {
			Object.assign(out, structuredCloneConfig(forModule as TestConfig));
		}
	}
	return out;
}

/** structuredClone that keeps functions (a .ts config's browser hook) */
function structuredCloneConfig(config: TestConfig): TestConfig {
	const { browser, ...rest } = config;
	const out = structuredClone(rest) as TestConfig;
	if (browser !== undefined) {
		out.browser = typeof browser === "function" ? browser : structuredClone(browser);
	}
	return out;
}

/** fnmatch-style glob (`*` any run of characters, `?` one character) as an anchored RegExp */
export function globToRegExp(pattern: string): RegExp {
	return new RegExp(`^${globBody(pattern)}$`);
}

/** The unanchored RegExp source of a glob */
export function globBody(pattern: string): string {
	return [...pattern]
		.map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\]/g, "\\$&")))
		.join("");
}

export function fnmatch(pattern: string, s: string): boolean {
	return globToRegExp(pattern).test(s);
}
