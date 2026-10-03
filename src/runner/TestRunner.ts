import type { BrowserContext } from "@playwright/test";
import { randomBytes } from "node:crypto";
import type { AbstractTestModule } from "../framework/AbstractTestModule.ts";
import { BrowserControl } from "../framework/BrowserControl.ts";
import { ConditionResult } from "../framework/Condition.ts";
import { args } from "../framework/DataUtils.ts";
import { TestInstanceEventLog, type LogEntry } from "../framework/EventLog.ts";
import { TestExecutionManager, sleep } from "../framework/execution.ts";
import { ImageService } from "../framework/ImageService.ts";
import type { JsonObject } from "../framework/json.ts";
import type { SuiteServer } from "../framework/server.ts";
import { Result, Status, type TestModuleClass } from "../framework/TestModule.ts";
import { VariantService } from "../framework/VariantService.ts";
import { VariantSelection } from "../framework/variants.ts";
import { findModule } from "../registry.ts";
import type { ClientDriverConfig, LoadedConfig, SuiteTargetConfig } from "./config.ts";

export interface ModuleRunOptions {
	moduleClass: TestModuleClass<AbstractTestModule>;
	variant: VariantSelection;
	loaded: LoadedConfig;
	server: SuiteServer;
	/** Playwright context used for scripted browser interaction (pages are created on demand) */
	context: BrowserContext;
	/** Seconds before the module is interrupted (default 150) */
	timeoutSeconds?: number;
	/** Live log sink (e.g. console output) */
	onLog?: (entry: LogEntry) => void;
	/** Values for the external URL override (defaults to the suite base URL) */
	externalUrlOverride?: string;
}

export interface ModuleRunResult {
	testId: string;
	testName: string;
	variant: Record<string, string>;
	status: Status;
	result: Result;
	entries: LogEntry[];
	screenshots: { name: string; png: Buffer }[];
	exposed: Record<string, string | null>;
	url: string;
	durationMs: number;
	/** Response from the RP driver (RP plans only) */
	clientDriverResult?: unknown;
	/** The emulated OP module's log (suite-vs-suite only) */
	nested?: { testName: string; result: Result; status: Status; entries: LogEntry[] };
}

/**
 * Port of DBTestPlanService.getModuleConfig: `override: { "<testName>": { ...keys } }` moves the module's overridden
 * top-level keys into the configuration (replacing, not merging) and removes `override` itself.
 */
export function applyOverride(config: JsonObject, moduleName: string): JsonObject {
	const override = config["override"];
	delete config["override"];
	if (override != null && typeof override === "object" && !Array.isArray(override)) {
		const overrides = override[moduleName];
		if (overrides != null && typeof overrides === "object" && !Array.isArray(overrides)) {
			for (const [k, v] of Object.entries(overrides)) {
				config[k] = v;
			}
		}
	}
	return config;
}

/** The "logged in user" owning the tests (Java: the OIDC subject/issuer of the suite user) */
const OWNER: Record<string, string> = {
	sub: process.env["CONFORMANCE_OWNER"] ?? "ci",
	iss: "openid-conformance-suite",
};

function newTestId(): string {
	return randomBytes(6).toString("hex");
}

/**
 * Port of the parts of runner/TestRunner.java + scripts/run-test-plan.py that run a single module instance to
 * completion.
 */
export async function runModule(opts: ModuleRunOptions): Promise<ModuleRunResult> {
	const started = Date.now();
	const testId = newTestId();
	const eventLog = new TestInstanceEventLog(testId, opts.onLog);
	const imageService = new ImageService(eventLog);
	const module = VariantService.newInstance(opts.moduleClass, opts.variant);
	const executionManager = new TestExecutionManager(testId, {
		onError: (error, source) => module.handleException(error, source),
		afterTask: () => module.forceReleaseLock(),
	});
	const config = applyOverride(
		structuredClone(opts.loaded.config) as JsonObject,
		opts.moduleClass.meta?.testName ?? "",
	);
	// suite-vs-suite: start the emulated OP (an RP test module of this suite) and point the OP tests at it
	const emulated = opts.loaded.suiteTarget ? await startEmulatedOp(opts.loaded.suiteTarget, opts) : null;
	if (emulated) {
		const server = (config["server"] as JsonObject | undefined) ?? {};
		server["discoveryUrl"] = emulated.url + "/.well-known/openid-configuration";
		config["server"] = server;
	}
	const browserConfig: JsonObject & { browser?: unknown } = { ...config };
	if (opts.loaded.browserHook) {
		browserConfig.browser = opts.loaded.browserHook;
	}
	const browser = new BrowserControl(
		browserConfig,
		testId,
		eventLog,
		executionManager,
		imageService,
		async () => opts.context,
	);
	module.setProperties(testId, OWNER, eventLog, browser, executionManager, imageService, {});

	const alias = typeof config["alias"] === "string" && config["alias"] ? config["alias"] : null;
	const { url, mtlsUrl } = opts.server.register(module, { alias });
	const externalUrlOverride = opts.externalUrlOverride ?? "";
	const testName = opts.moduleClass.meta?.testName ?? opts.moduleClass.name;

	eventLog.log(
		"TEST-RUNNER",
		args(
			"msg",
			"Test instance " + testId + " created",
			"result",
			ConditionResult.INFO,
			"baseUrl",
			url,
			"baseMtlsUrl",
			mtlsUrl,
			"config",
			config,
			"alias",
			alias,
			"testName",
			testName,
			"variant",
			opts.variant.getVariant(),
		),
	);

	executionManager.runInBackground(async () => {
		await module.configure(config, url, externalUrlOverride, mtlsUrl);
		if (module.getStatus() === Status.CONFIGURED) {
			if (!module.autoStart()) {
				// as upstream's run-test-plan.py does for oidcc-server-rotate-keys: a module that waits for the user to
				// press 'Start' (after rotating the OP's keys) is started right away in an unattended run
				eventLog.log(
					"TEST-RUNNER",
					args(
						"msg",
						"Starting the test module without waiting for the user to press 'Start' (unattended run)",
						"result",
						ConditionResult.INFO,
					),
				);
			}
			await module.start();
		}
		return "done";
	}, "test");

	const timeoutMs = (opts.timeoutSeconds ?? 150) * 1000;
	let clientDriverResult: unknown;
	const driver = opts.loaded.clientDriver;
	const finished = module.whenFinished();
	const timeout = sleep(timeoutMs).then(() => "timeout" as const);
	if (driver) {
		// RP plans: once the emulated OP is waiting for the RP, kick the RP off (Java: run-test-plan.py waits for
		// WAITING then runs the client, then waits for FINISHED)
		const waiting = waitForStatus(module, [Status.WAITING, Status.FINISHED, Status.INTERRUPTED], timeoutMs);
		const which = await Promise.race([waiting, timeout]);
		if (which === "timeout") {
			await module.stop("Timed out waiting for the test to finish setting up");
		} else if (module.getStatus() === Status.WAITING) {
			clientDriverResult = await driveClient(driver, url, testName, opts.variant.getVariant(), config, eventLog);
		}
	}
	const outcome = await Promise.race([finished.then(() => "finished" as const), timeout]);
	if (outcome === "timeout") {
		await module.stop(`Timed out after ${timeoutMs / 1000} seconds waiting for the test to finish`);
	}
	await executionManager.drain();
	opts.server.unregister(module);

	let nested: ModuleRunResult["nested"];
	if (emulated) {
		if (emulated.module.getStatus() !== Status.FINISHED && emulated.module.getStatus() !== Status.INTERRUPTED) {
			await emulated.module.stop("The test under test has finished");
		}
		await emulated.executionManager.drain();
		opts.server.unregister(emulated.module);
		nested = {
			testName: emulated.module.getName(),
			result: emulated.module.getResult(),
			status: emulated.module.getStatus(),
			entries: emulated.eventLog.entries,
		};
	}

	return {
		nested,
		testId,
		testName,
		variant: opts.variant.getVariant(),
		status: module.getStatus(),
		result: module.getResult(),
		entries: eventLog.entries,
		screenshots: browser.screenshots,
		exposed: module.getExposedValues(),
		url,
		durationMs: Date.now() - started,
		clientDriverResult,
	};
}

/**
 * Start an RP test module of this suite to act as the OP under test (upstream: "OP-vs-RP pairing").
 */
async function startEmulatedOp(
	target: SuiteTargetConfig,
	opts: ModuleRunOptions,
): Promise<{
	module: AbstractTestModule;
	url: string;
	executionManager: TestExecutionManager;
	eventLog: TestInstanceEventLog;
}> {
	const moduleClass = findModule(target.module);
	if (!moduleClass) {
		throw new Error(`suite_target.module '${target.module}' is not a known test module`);
	}
	const testId = newTestId();
	const eventLog = new TestInstanceEventLog(testId, opts.onLog);
	const imageService = new ImageService(eventLog);
	// suite_target.variant wins; a parameter the emulated module declares but the config leaves out is taken from
	// the variant of the module under test when it has one (e.g. client_auth_type), so the two sides agree
	const variant: Record<string, string> = {};
	for (const p of VariantService.parametersOf(moduleClass)) {
		const name = p.parameter.name;
		const value = target.variant?.[name] ?? opts.variant.getVariant()[name];
		if (value !== undefined) {
			variant[name] = value;
		}
	}
	const module = VariantService.newInstance(moduleClass, new VariantSelection(variant));
	// OP test modules call the emulated OP's endpoints after its own single flow has finished (second userinfo
	// request, a second authorization, ...)
	module.setKeepServingAfterFinish(true);
	const executionManager = new TestExecutionManager(testId, {
		onError: (error, source) => module.handleException(error, source),
		afterTask: () => module.forceReleaseLock(),
	});
	const config = structuredClone(target.config ?? {}) as JsonObject;
	const browser = new BrowserControl(
		config,
		testId,
		eventLog,
		executionManager,
		imageService,
		async () => opts.context,
	);
	module.setProperties(testId, OWNER, eventLog, browser, executionManager, imageService, {});
	const alias = target.alias ?? "emulated-op";
	const { url, mtlsUrl } = opts.server.register(module, { alias });
	eventLog.log(
		"TEST-RUNNER",
		args(
			"msg",
			"Emulated OP test instance " + testId + " created",
			"result",
			ConditionResult.INFO,
			"baseUrl",
			url,
			"config",
			config,
			"alias",
			alias,
			"testName",
			module.getName(),
		),
	);
	executionManager.runInBackground(async () => {
		await module.configure(config, url, "", mtlsUrl);
		if (module.getStatus() === Status.CONFIGURED && module.autoStart()) {
			await module.start();
		}
		return "done";
	}, "test");
	const status = await waitForStatus(module, [Status.WAITING, Status.FINISHED, Status.INTERRUPTED], 60_000);
	if (status !== Status.WAITING) {
		throw new Error(`emulated OP module '${target.module}' did not reach WAITING (status ${status}); see its log`);
	}
	return { module, url, executionManager, eventLog };
}

async function waitForStatus(module: AbstractTestModule, statuses: Status[], timeoutMs: number): Promise<Status> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (statuses.includes(module.getStatus())) {
			return module.getStatus();
		}
		await sleep(50);
	}
	return module.getStatus();
}

/**
 * Kick off the RP under test for one module (see targets/openid-client-rp/README.md for the contract).
 */
async function driveClient(
	driver: ClientDriverConfig,
	suiteUrl: string,
	testName: string,
	variant: Record<string, string>,
	config: JsonObject,
	eventLog: TestInstanceEventLog,
): Promise<unknown> {
	const url = new URL(driver.startUrl);
	url.searchParams.set("issuer", suiteUrl.endsWith("/") ? suiteUrl : suiteUrl + "/");
	url.searchParams.set("module", testName);
	url.searchParams.set("variant", JSON.stringify(variant));
	url.searchParams.set(
		"client_metadata_defaults",
		JSON.stringify((config["client_metadata_defaults"] as JsonObject | undefined) ?? {}),
	);
	if (typeof config["alias"] === "string") {
		url.searchParams.set("alias", config["alias"]);
	}
	const client = (config["client"] as JsonObject | undefined) ?? {};
	for (const k of ["client_id", "client_secret", "jwks"]) {
		const v = client[k];
		if (v != null) {
			url.searchParams.set(k, typeof v === "string" ? v : JSON.stringify(v));
		}
	}
	for (const [k, v] of Object.entries(driver.params ?? {})) {
		url.searchParams.set(k, v);
	}
	eventLog.log(
		"TEST-RUNNER",
		args("msg", "Starting the relying party under test", "url", url.toString(), "result", ConditionResult.INFO),
	);
	try {
		const res = await fetch(url, { signal: AbortSignal.timeout((driver.timeoutSeconds ?? 120) * 1000) });
		const text = await res.text();
		let body: unknown = text;
		try {
			body = JSON.parse(text);
		} catch {
			// not json
		}
		eventLog.log(
			"TEST-RUNNER",
			args(
				"msg",
				"Relying party under test finished",
				"status",
				res.status,
				"response",
				body,
				"result",
				res.ok ? ConditionResult.INFO : ConditionResult.WARNING,
			),
		);
		return { status: res.status, body };
	} catch (e) {
		eventLog.log(
			"TEST-RUNNER",
			args(
				"msg",
				"Relying party under test could not be driven: " + (e as Error).message,
				"result",
				ConditionResult.WARNING,
			),
		);
		return { error: (e as Error).message };
	}
}
