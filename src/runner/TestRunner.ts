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
import type { VariantSelection } from "../framework/variants.ts";
import type { ClientDriverConfig, LoadedConfig } from "./config.ts";

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
}

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
	const config = structuredClone(opts.loaded.config) as JsonObject;
	const browserConfig: JsonObject & { browser?: unknown } = { ...config };
	if (opts.loaded.browserHook) {
		browserConfig.browser = opts.loaded.browserHook;
	}
	const browser = new BrowserControl(browserConfig, testId, eventLog, executionManager, imageService, async () => opts.context);
	module.setProperties(testId, null, eventLog, browser, executionManager, imageService, {});

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
		if (module.getStatus() === Status.CONFIGURED && module.autoStart()) {
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

	return {
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
	url.searchParams.set("client_metadata_defaults", JSON.stringify((config["client_metadata_defaults"] as JsonObject | undefined) ?? {}));
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
	eventLog.log("TEST-RUNNER", args("msg", "Starting the relying party under test", "url", url.toString(), "result", ConditionResult.INFO));
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
			args("msg", "Relying party under test finished", "status", res.status, "response", body, "result", res.ok ? ConditionResult.INFO : ConditionResult.WARNING),
		);
		return { status: res.status, body };
	} catch (e) {
		eventLog.log("TEST-RUNNER", args("msg", "Relying party under test could not be driven: " + (e as Error).message, "result", ConditionResult.WARNING));
		return { error: (e as Error).message };
	}
}
