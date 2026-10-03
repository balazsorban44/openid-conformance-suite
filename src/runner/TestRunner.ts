import type { BrowserContext } from "@playwright/test";
import { randomBytes } from "node:crypto";
import type { AbstractTestModule } from "../framework/AbstractTestModule.ts";
import { BrowserControl, type BrowserHook } from "../framework/BrowserControl.ts";
import { ConditionResult } from "../framework/Condition.ts";
import { TestInstanceEventLog, type LogEntry } from "../framework/EventLog.ts";
import { TestExecutionManager, sleep } from "../framework/execution.ts";
import { ImageService } from "../framework/ImageService.ts";
import type { JsonObject } from "../framework/json.ts";
import type { SuiteServer } from "../framework/server.ts";
import { Result, Status, type TestModuleClass } from "../framework/TestModule.ts";
import { newInstance, parametersOf } from "../framework/VariantService.ts";
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
			Object.assign(config, overrides);
		}
	}
	return config;
}

/** The "logged in user" owning the tests (Java: the OIDC subject/issuer of the suite user) */
const OWNER: Record<string, string> = {
	sub: process.env["CONFORMANCE_OWNER"] ?? "ci",
	iss: "openid-conformance-suite",
};

const SETTLED = [Status.WAITING, Status.FINISHED, Status.INTERRUPTED];

/** A test module instance wired to its log, execution manager and browser, and registered with the suite server */
interface Instance {
	testId: string;
	eventLog: TestInstanceEventLog;
	module: AbstractTestModule;
	executionManager: TestExecutionManager;
	browser: BrowserControl;
	url: string;
	mtlsUrl: string;
	/** Resolves with the module's status once it is one of `statuses` */
	reached: (statuses: Status[]) => Promise<Status>;
}

/** Port of the instance setup in runner/TestRunner.java createTest() */
function createInstance(
	moduleClass: TestModuleClass<AbstractTestModule>,
	variant: VariantSelection,
	browserConfig: ConstructorParameters<typeof BrowserControl>[0],
	alias: string | null,
	opts: ModuleRunOptions,
): Instance {
	const testId = randomBytes(6).toString("hex");
	const eventLog = new TestInstanceEventLog(testId, opts.onLog);
	const imageService = new ImageService(eventLog);
	const module = newInstance(moduleClass, variant);
	const executionManager = new TestExecutionManager(testId, {
		onError: (error, source) => module.handleException(error, source),
		afterTask: () => module.forceReleaseLock(),
	});
	const browser = new BrowserControl(
		browserConfig,
		testId,
		eventLog,
		executionManager,
		imageService,
		async () => opts.context,
	);
	module.attach({ id: testId, owner: OWNER, eventLog, browser, executionManager, imageService });
	const reached = (statuses: Status[]): Promise<Status> => module.whenStatus(...statuses);
	const { url, mtlsUrl } = opts.server.register(module, { alias });
	return { testId, eventLog, module, executionManager, browser, url, mtlsUrl, reached };
}

/**
 * Configure and start the module in the background. A module that waits for the user to press 'Start'
 * (`autoStart() == false`) is only started when `unattended`.
 */
function startInBackground(inst: Instance, config: JsonObject, externalUrlOverride: string, unattended: boolean): void {
	const { module, eventLog } = inst;
	inst.executionManager.runInBackground(async () => {
		await module.configure(config, inst.url, externalUrlOverride, inst.mtlsUrl);
		if (module.getStatus() === Status.CONFIGURED && (module.autoStart() || unattended)) {
			if (!module.autoStart()) {
				// as upstream's run-test-plan.py does for oidcc-server-rotate-keys: a module that waits for the user to
				// press 'Start' (after rotating the OP's keys) is started right away in an unattended run
				eventLog.log("TEST-RUNNER", {
					msg: "Starting the test module without waiting for the user to press 'Start' (unattended run)",
					result: ConditionResult.INFO,
				});
			}
			await module.start();
		}
		return "done";
	}, "test");
}

/**
 * Port of the parts of runner/TestRunner.java + scripts/run-test-plan.py that run a single module instance to
 * completion.
 */
export async function runModule(opts: ModuleRunOptions): Promise<ModuleRunResult> {
	const started = Date.now();
	const testName = opts.moduleClass.meta?.testName ?? opts.moduleClass.name;
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
	const browserConfig: JsonObject & { browser?: BrowserHook } = { ...config };
	if (opts.loaded.browserHook) {
		browserConfig.browser = opts.loaded.browserHook;
	}
	const alias = typeof config["alias"] === "string" && config["alias"] ? config["alias"] : null;
	const inst = createInstance(opts.moduleClass, opts.variant, browserConfig, alias, opts);
	const { testId, eventLog, module, url } = inst;

	eventLog.log("TEST-RUNNER", {
		msg: "Test instance " + testId + " created",
		result: ConditionResult.INFO,
		baseUrl: url,
		baseMtlsUrl: inst.mtlsUrl,
		config,
		alias,
		testName,
		variant: opts.variant.getVariant(),
	});
	startInBackground(inst, config, opts.externalUrlOverride ?? "", true);

	const timeoutMs = (opts.timeoutSeconds ?? 150) * 1000;
	const timeout = sleep(timeoutMs).then(() => "timeout" as const);
	let clientDriverResult: unknown;
	const driver = opts.loaded.clientDriver;
	if (driver) {
		// RP plans: once the emulated OP is waiting for the RP, kick the RP off (Java: run-test-plan.py waits for
		// WAITING then runs the client, then waits for FINISHED)
		if ((await Promise.race([inst.reached(SETTLED), timeout])) === "timeout") {
			await module.stop("Timed out waiting for the test to finish setting up");
		} else if (module.getStatus() === Status.WAITING) {
			clientDriverResult = await driveClient(driver, url, testName, opts.variant.getVariant(), config, eventLog);
		}
	}
	const outcome = await Promise.race([module.whenFinished().then(() => "finished" as const), timeout]);
	if (outcome === "timeout") {
		await module.stop(`Timed out after ${timeoutMs / 1000} seconds waiting for the test to finish`);
	}
	await inst.executionManager.drain();
	opts.server.unregister(module);

	let nested: ModuleRunResult["nested"];
	if (emulated) {
		const op = emulated.module;
		if (op.getStatus() !== Status.FINISHED && op.getStatus() !== Status.INTERRUPTED) {
			await op.stop("The test under test has finished");
		}
		await emulated.executionManager.drain();
		opts.server.unregister(op);
		nested = {
			testName: op.getName(),
			result: op.getResult(),
			status: op.getStatus(),
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
		screenshots: inst.browser.screenshots,
		exposed: module.getExposedValues(),
		url,
		durationMs: Date.now() - started,
		clientDriverResult,
	};
}

/**
 * Start an RP test module of this suite to act as the OP under test (upstream: "OP-vs-RP pairing").
 */
async function startEmulatedOp(target: SuiteTargetConfig, opts: ModuleRunOptions): Promise<Instance> {
	const moduleClass = findModule(target.module);
	if (!moduleClass) {
		throw new Error(`suite_target.module '${target.module}' is not a known test module`);
	}
	// suite_target.variant wins; a parameter the emulated module declares but the config leaves out is taken from
	// the variant of the module under test when it has one (e.g. client_auth_type), so the two sides agree
	const variant: Record<string, string> = {};
	for (const p of parametersOf(moduleClass)) {
		const name = p.parameter.name;
		const value = target.variant?.[name] ?? opts.variant.getVariant()[name];
		if (value !== undefined) {
			variant[name] = value;
		}
	}
	const config = structuredClone(target.config ?? {}) as JsonObject;
	const alias = target.alias ?? "emulated-op";
	const inst = createInstance(moduleClass, new VariantSelection(variant), config, alias, opts);
	// OP test modules call the emulated OP's endpoints after its own single flow has finished (second userinfo
	// request, a second authorization, ...)
	inst.module.setKeepServingAfterFinish(true);
	inst.eventLog.log("TEST-RUNNER", {
		msg: "Emulated OP test instance " + inst.testId + " created",
		result: ConditionResult.INFO,
		baseUrl: inst.url,
		config,
		alias,
		testName: inst.module.getName(),
	});
	startInBackground(inst, config, "", false);
	const status = await Promise.race([inst.reached(SETTLED), sleep(60_000).then(() => inst.module.getStatus())]);
	if (status !== Status.WAITING) {
		throw new Error(`emulated OP module '${target.module}' did not reach WAITING (status ${status}); see its log`);
	}
	return inst;
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
	const client = (config["client"] as JsonObject | undefined) ?? {};
	const params: Record<string, string> = {
		issuer: suiteUrl.endsWith("/") ? suiteUrl : suiteUrl + "/",
		module: testName,
		variant: JSON.stringify(variant),
		client_metadata_defaults: JSON.stringify((config["client_metadata_defaults"] as JsonObject | undefined) ?? {}),
	};
	if (typeof config["alias"] === "string") {
		params["alias"] = config["alias"];
	}
	for (const k of ["client_id", "client_secret", "jwks"]) {
		const v = client[k];
		if (v != null) {
			params[k] = typeof v === "string" ? v : JSON.stringify(v);
		}
	}
	for (const [k, v] of Object.entries({ ...params, ...driver.params })) {
		url.searchParams.set(k, v);
	}
	eventLog.log("TEST-RUNNER", {
		msg: "Starting the relying party under test",
		url: url.toString(),
		result: ConditionResult.INFO,
	});
	try {
		const res = await fetch(url, { signal: AbortSignal.timeout((driver.timeoutSeconds ?? 120) * 1000) });
		const text = await res.text();
		let body: unknown = text;
		try {
			body = JSON.parse(text);
		} catch {
			// not json
		}
		eventLog.log("TEST-RUNNER", {
			msg: "Relying party under test finished",
			status: res.status,
			response: body,
			result: res.ok ? ConditionResult.INFO : ConditionResult.WARNING,
		});
		return { status: res.status, body };
	} catch (e) {
		eventLog.log("TEST-RUNNER", {
			msg: "Relying party under test could not be driven: " + (e as Error).message,
			result: ConditionResult.WARNING,
		});
		return { error: (e as Error).message };
	}
}
