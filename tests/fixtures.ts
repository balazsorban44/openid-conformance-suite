/**
 * The fixtures every conformance spec uses.
 *
 *   test.describe("oidcc-basic-certification-test-plan", () => {
 *     test.use({ plan: { name: "oidcc-basic-certification-test-plan", variant: { response_type: "code", ... } } });
 *     test("oidcc-server: ...", async ({ op, client }) => { ... });
 *   });
 *
 * - `op`: the OP under test, discovered (or configured), its keys fetched and checked, plus the suite's server,
 *   scripted browser and event log for this test. One per test.
 * - `client` / `client2`: the client(s), dynamically registered or taken from the configuration (per the
 *   client_registration variant); a registered client is unregistered after the test.
 * - `variant`: the variant (the plan's fixed values + the selection from CONFORMANCE_VARIANT / the project).
 *
 * Selection (environment): CONFORMANCE_PROJECT (a project from src/runner/projects.ts) or CONFORMANCE_CONFIG +
 * CONFORMANCE_VARIANT; CONFORMANCE_MODULE (a glob on module names) is applied by playwright.config.ts as `grep`.
 * CONFORMANCE_TLS=1 serves the suite over https (configs/certs, or CONFORMANCE_TLS_CERT / CONFORMANCE_TLS_KEY).
 *
 * After each test the log is attached (log.json, log.html, module-report.json, target-output.txt) and compared with
 * the expected failures/skips of the configuration, exactly like upstream's CI (run-test-plan.py): an unexpected
 * failure, warning or skip fails the test; a test stopped by an expected failure passes (expected to fail).
 */
import { test as base, expect, type TestInfo } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import * as discovery from "../src/op/discovery.ts";
import { loadServerKeys } from "../src/op/jwks.ts";
import type { Op, OpVariant } from "../src/op/op.ts";
import * as registration from "../src/op/registration.ts";
import type { RegisteredClient } from "../src/op/registration.ts";
import { projects } from "../src/runner/projects.ts";
import { createBrowser } from "../src/suite/browser.ts";
import { block, condition, soft } from "../src/suite/conditions.ts";
import { loadConfig, moduleConfig, readConfig, type LoadedConfig, type TestConfig } from "../src/suite/config.ts";
import { analyzeResultLogs, describeProblems } from "../src/suite/expected.ts";
import { createLog, renderLogHtml, resultOf, useLog, type EventLog, type LogEntry } from "../src/suite/log.ts";
import type { ModuleReport } from "../src/suite/report.ts";
import { startServer, type TestServer } from "../src/suite/server.ts";
import { startTarget, type RunningTarget } from "../src/suite/target.ts";

export { expect };

const root = resolve(import.meta.dirname, "..");

/** The plan a describe block belongs to: its name and the variant values it fixes */
export interface PlanOption {
	name: string;
	variant: Record<string, string>;
}

/** What the per-test setup provides to the op/rp fixtures */
interface Conformance {
	testName: string;
	log: EventLog;
	config: TestConfig;
	server: TestServer;
	browser: ReturnType<typeof createBrowser>;
}

interface Suite {
	loaded: LoadedConfig;
	target: RunningTarget | null;
	/** The user's variant selection (CONFORMANCE_VARIANT or the project's) */
	selection: Record<string, string>;
}

interface Fixtures {
	plan: PlanOption;
	variant: OpVariant;
	conformance: Conformance;
	op: Op;
	client: RegisteredClient;
	client2: RegisteredClient;
}

/** "[k=v][k2=v2]" -> { k: v, k2: v2 } */
export function parseVariant(s: string): Record<string, string> {
	return Object.fromEntries([...s.matchAll(/\[([^=\]]+)=([^\]]*)\]/g)].map((m) => [m[1], m[2]]));
}

/** { k: v } -> "[k=v]..." sorted by name (upstream's variant string) */
export function variantString(v: Record<string, string>): string {
	return Object.keys(v)
		.sort()
		.map((k) => `[${k}=${v[k]}]`)
		.join("");
}

function selection(): { config: string | undefined; variant: string } {
	const project = projects.find((p) => p.name === process.env["CONFORMANCE_PROJECT"]);
	return {
		config: process.env["CONFORMANCE_CONFIG"] ?? project?.config,
		variant: process.env["CONFORMANCE_VARIANT"] ?? project?.variant ?? "",
	};
}

function tls(): { cert: string; key: string } | undefined {
	if (!process.env["CONFORMANCE_TLS"] || process.env["CONFORMANCE_TLS"] === "0") {
		return undefined;
	}
	const pem = (env: string, file: string) =>
		readFileSync(process.env[env] ?? resolve(root, "configs/certs", file), "utf8");
	return { cert: pem("CONFORMANCE_TLS_CERT", "localhost.crt"), key: pem("CONFORMANCE_TLS_KEY", "localhost.key") };
}

/** The module a test is for: its title up to the first ':' ("oidcc-server: ..." -> "oidcc-server") */
export function moduleName(title: string): string {
	return title.split(":")[0].trim();
}

export const test = base.extend<Fixtures, { suite: Suite }>({
	plan: [{ name: "", variant: {} }, { option: true }],

	suite: [
		// oxlint-disable-next-line no-empty-pattern -- Playwright requires the destructuring pattern for fixture arguments
		async ({}, use) => {
			const sel = selection();
			if (!sel.config) {
				throw new Error(
					"No configuration: set CONFORMANCE_PROJECT (see `openid-conformance projects`) or CONFORMANCE_CONFIG",
				);
			}
			const path = resolve(root, sel.config);
			const raw = await readConfig(path);
			const target = raw["target"]
				? await startTarget(raw["target"] as never, process.env["CONFORMANCE_CWD"] ?? process.cwd())
				: null;
			try {
				const loaded = await loadConfig(path, raw, target?.vars ?? {});
				await use({ loaded, target, selection: parseVariant(sel.variant) });
			} finally {
				if (!process.env["CONFORMANCE_KEEP_SERVER"]) {
					await target?.stop();
				}
			}
		},
		{ scope: "worker" },
	],

	variant: async ({ plan, suite }, use) => {
		await use({ ...suite.selection, ...plan.variant } as OpVariant);
	},

	conformance: async ({ plan, variant, suite, context }, use, testInfo) => {
		const testName = moduleName(testInfo.title);
		const started = Date.now();
		const log = createLog(undefined, process.env["CONFORMANCE_VERBOSE"] ? printEntry : undefined);
		const uninstall = useLog(log, { testName, step: (name, fn) => test.step(name, fn) });
		const config = moduleConfig(suite.loaded.config, testName);
		const screenshots: { name: string; png: Buffer }[] = [];
		const server = await startServer({
			log,
			testName,
			alias: typeof config.alias === "string" ? config.alias : null,
			tls: tls(),
		});
		const browser = createBrowser({
			context,
			automation: config.browser,
			log,
			verbose: config.browser_verbose === true,
			onScreenshot: (name, png) => screenshots.push({ name, png }),
		});
		log.log("TEST-RUNNER", {
			msg: "Test instance " + log.testId + " created",
			result: "INFO",
			baseUrl: server.baseUrl,
			config: { ...config, browser: typeof config.browser === "function" ? "(function)" : config.browser },
			alias: config.alias ?? null,
			testName,
			variant,
		});
		try {
			await use({ testName, log, config, server, browser });
		} finally {
			await server.close();
			uninstall();
			await finish({ testInfo, plan, variant, suite, log, testName, started, screenshots });
		}
	},

	op: async ({ conformance, variant }, use) => {
		const { config, log, server, browser, testName } = conformance;
		// upstream: condition/client/CreateRedirectUri.java
		const redirectUri = server.baseUrl + "/callback";
		condition("CreateRedirectUri").success("Created redirect URI", { redirect_uri: redirectUri });

		const metadata =
			variant.server_metadata === "static"
				? discovery.getStaticServerConfiguration(config)
				: (await discovery.getDynamicServerConfiguration(config)).metadata;
		// make sure the server configuration passes some basic sanity checks
		discovery.checkServerConfiguration(metadata);
		discovery.extractTLSTestValuesFromServerConfiguration(metadata);
		const jwks = await loadServerKeys(metadata);
		await use({
			testName,
			testId: log.testId,
			config,
			variant,
			metadata,
			jwks,
			baseUrl: server.baseUrl,
			redirectUri,
			server,
			browser,
			log,
		});
	},

	client: async ({ op }, use) => {
		await useClient(op, "client", use);
	},

	client2: async ({ op }, use) => {
		await useClient(op, "client2", use);
	},
});

/**
 * Registers (or takes from the configuration) the client, makes sure the OP supports the variant's client
 * authentication, and unregisters a registered client after the test.
 *
 * upstream: AbstractOIDCCServerTest.configureClient / completeClientConfiguration / unregisterClient
 */
async function useClient(
	op: Op,
	configKey: "client" | "client2",
	use: (c: RegisteredClient) => Promise<void>,
): Promise<void> {
	let registered: RegisteredClient;
	if (op.variant.client_registration === "static_client") {
		const client = registration.getStaticClientConfiguration(op.config, configKey);
		registered = { client, keys: registration.configureStaticClientKeys(client), dynamic: false };
	} else {
		registered = await registration.registerClient({
			testId: op.testId,
			metadata: op.metadata,
			config: op.config,
			configKey,
			responseType: op.variant.response_type,
			clientAuthType: op.variant.client_auth_type,
			redirectUri: op.redirectUri,
		});
	}
	registration.setScopeInClientConfigurationToOpenId(registered.client);
	if (op.variant.server_metadata === "discovery") {
		soft(() => discovery.ensureServerConfigurationSupportsClientAuth(op.metadata, op.variant.client_auth_type));
	}
	try {
		await use(registered);
	} finally {
		if (registered.dynamic) {
			await block("Unregister dynamically registered client", () =>
				soft(() => registration.unregisterDynamicallyRegisteredClient(registered.client), "warning"),
			);
		}
	}
}

/**
 * Attaches the log and compares it with the expected failures/skips (upstream run-test-plan.py
 * analyze_result_logs): unexpected findings fail the test, a test stopped only by expected failures passes.
 */
async function finish(args: {
	testInfo: TestInfo;
	plan: PlanOption;
	variant: OpVariant;
	suite: Suite;
	log: EventLog;
	testName: string;
	started: number;
	screenshots: { name: string; png: Buffer }[];
}): Promise<void> {
	const { testInfo, plan, variant, suite, log, testName } = args;
	const entries = log.entries;
	const skipped = testInfo.status === "skipped";
	// a failing check throws "<Condition>: <message>" after logging it; any other error stopped the test unexpectedly
	const conditionFailures = entries
		.filter((e) => e["result"] === "FAILURE" || e["result"] === "WARNING" || e["result"] === "INFO")
		.map((e) => `${e.src}: ${String(e["msg"] ?? "")}`);
	const unexpectedErrors = testInfo.errors.filter((e) => !conditionFailures.some((m) => (e.message ?? "").includes(m)));
	for (const e of unexpectedErrors) {
		log.log(testName, { msg: (e.message ?? String(e.value)).split("\n")[0], result: "FAILURE", stacktrace: e.stack });
	}
	const status = unexpectedErrors.length > 0 ? "INTERRUPTED" : "FINISHED";
	const result = resultOf(entries, skipped);
	const variantObj = Object.fromEntries(Object.entries(variant).filter(([, v]) => typeof v === "string")) as Record<
		string,
		string
	>;
	const analysis = analyzeResultLogs(
		testName,
		variantObj,
		result,
		entries,
		suite.loaded.expectedFailures,
		suite.loaded.expectedSkips,
		suite.loaded.filename,
	);
	const vs = variantString(variantObj);
	const report: ModuleReport = {
		plan: plan.name,
		testName,
		variant: variantObj,
		variantString: vs,
		testId: log.testId,
		status,
		result,
		ok: analysis.ok && status !== "INTERRUPTED",
		durationMs: Date.now() - args.started,
		analysis,
		title: testInfo.title,
	};

	const attach = async (name: string, body: string | Buffer, contentType: string) => {
		const path = testInfo.outputPath(name);
		writeFileSync(path, body);
		await testInfo.attach(name, { path, contentType });
	};
	await attach("log.json", JSON.stringify(entries, null, 2), "application/json");
	await attach(
		"log.html",
		renderLogHtml(`${testName}${vs}`, entries, { result, status, variant: variantObj }),
		"text/html",
	);
	for (const s of args.screenshots) {
		await attach(s.name + ".png", s.png, "image/png");
	}
	await attach("module-report.json", JSON.stringify(report), "application/json");
	if (suite.target && suite.target.output.length > 0) {
		await attach("target-output.txt", suite.target.output.join(""), "text/plain");
	}

	testInfo.annotations.push({ type: "variant", description: vs });
	for (const f of analysis.expected_failures) {
		testInfo.annotations.push({ type: "expected failure", description: `${f.src}: ${f.msg ?? ""}` });
	}
	const problems = describeProblems(analysis);
	if (report.ok) {
		if (testInfo.status === "failed") {
			// stopped by a failure the configuration expects: the test did what it should
			testInfo.expectedStatus = "failed";
		}
		return;
	}
	if (problems.length > 0) {
		throw new Error(`${testName}${vs} (result ${result}): ${problems.join("; ")}. See the log.html attachment.`);
	}
}

/** CONFORMANCE_VERBOSE: stream the log to the console */
function printEntry(e: LogEntry): void {
	const extra = ["url", "error", "request_uri", "response_status_code"]
		.filter((k) => e[k] != null)
		.map((k) => `${k}=${String(e[k])}`)
		.join(" ");
	process.stdout.write(
		`${e.src}: ${String(e["msg"] ?? "")} ${e["result"] ? `[${String(e["result"])}]` : ""} ${extra}\n`,
	);
}
