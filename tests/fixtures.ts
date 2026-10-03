/**
 * The fixtures every conformance spec uses.
 *
 *   test.describe("oidcc-basic-certification-test-plan", () => {
 *     test.use({ plan: { name: "oidcc-basic-certification-test-plan", variant: { response_type: "code", ... } } });
 *     test("oidcc-server: ...", async ({ op, client }) => { ... });
 *   });
 *
 * - `op`: the OP under test, discovered (or configured), its keys fetched and checked, plus the suite's server,
 *   scripted browser and event log for this test. One per test. `registrationOp` is the same OP without the keys
 *   (the modules that only register clients, upstream AbstractOIDCCDynamicRegistrationTest).
 * - `client` / `client2`: the client(s), dynamically registered or taken from the configuration (per the
 *   client_registration variant); a registered client is unregistered after the test.
 * - `configureClient(setup?)`: the same client set up where the test calls it, with what the module changes about it
 *   (registration request, static client key, scope, the second client); `client` / `client2` are
 *   `configureClient()` / `configureClient({ configKey: "client2" })`.
 * - `rp`: for RP tests, the emulated OP (`rp.start(options)`, on the test's own server; its issuer is the server's
 *   base url) and the client driver that makes the RP under test log in against it (`rp.driveClient()`).
 * - `variant`: the variant (the plan's fixed values + the selection from CONFORMANCE_VARIANT / the project).
 * - `skipTest(reason)` (a function, not a fixture): upstream's fireTestSkipped.
 * - `suiteTarget` (suite-vs-suite, the config's `suite_target`): this suite's emulated OP, started per test on a
 *   server and log of its own, as the OP the `op` fixture discovers (tests/suite-target.ts); null otherwise.
 *
 * A module listed in the project's `skipModules` is skipped (the `conformance` fixture) with the reason given there.
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
import type { Op, OpVariant, RegistrationOp } from "../src/op/op.ts";
import * as registration from "../src/op/registration.ts";
import type { ClientSetup, RegisteredClient } from "../src/op/registration.ts";
import { projects } from "../src/runner/projects.ts";
import { createBrowser } from "../src/suite/browser.ts";
import { block, condition, logTestSkipped, soft } from "../src/suite/conditions.ts";
import { loadConfig, moduleConfig, readConfig, type LoadedConfig, type TestConfig } from "../src/suite/config.ts";
import { analyzeResultLogs, describeProblems } from "../src/suite/expected.ts";
import { createLog, renderLogHtml, resultOf, useLog, type EventLog, type LogEntry } from "../src/suite/log.ts";
import type { ModuleReport } from "../src/suite/report.ts";
import { startServer, type TestServer } from "../src/suite/server.ts";
import { startTarget, type RunningTarget } from "../src/suite/target.ts";
import type { RpVariant } from "../src/rp/op.ts";
import { createRp, type Rp } from "../src/rp/rp.ts";
import { startSuiteTarget, type SuiteTarget } from "./suite-target.ts";

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
	/** The project's modules that are not run: testName -> why (the skip reason) */
	skipModules: Record<string, string>;
}

interface Fixtures {
	plan: PlanOption;
	variant: OpVariant;
	conformance: Conformance;
	suiteTarget: SuiteTarget | null;
	registrationOp: RegistrationOp;
	op: Op;
	client: RegisteredClient;
	client2: RegisteredClient;
	configureClient: ConfigureClient;
	rp: Rp;
}

/**
 * Sets up a client, called by the test where the module configures it (the `client` / `client2` fixtures call it
 * before the test): registers it (or takes it from the configuration), applies the module's `setup` (ClientSetup: the
 * registration request additions, the static client key, completeClientConfiguration, the second client). Conditions
 * the module runs before the client is configured (upstream configureClient overrides) are simply called before it.
 * Registered clients are unregistered after the test, in the order they were set up.
 */
export type ConfigureClient = (setup?: ClientSetup) => Promise<RegisteredClient>;

/**
 * Ends the test as skipped, as upstream's fireTestSkipped does: the SKIPPED entry in the module's log (the module
 * result is SKIPPED, compared with the expected skips of the configuration) and Playwright's skip.
 */
export function skipTest(reason: string): never {
	logTestSkipped(reason);
	test.skip(true, reason);
	throw new Error("unreachable: test.skip() ends the test");
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

function selection(): { config: string | undefined; variant: string; skipModules: Record<string, string> } {
	const project = projects.find((p) => p.name === process.env["CONFORMANCE_PROJECT"]);
	return {
		config: process.env["CONFORMANCE_CONFIG"] ?? project?.config,
		variant: process.env["CONFORMANCE_VARIANT"] ?? project?.variant ?? "",
		skipModules: project?.skipModules ?? {},
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
				await use({ loaded, target, selection: parseVariant(sel.variant), skipModules: sel.skipModules });
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
		// a module the project does not run (e.g. one the suite-vs-suite emulated OP cannot serve)
		testInfo.skip(testName in suite.skipModules, suite.skipModules[testName]);
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

	suiteTarget: async ({ conformance, variant, suite }, use, testInfo) => {
		const target = suite.loaded.suiteTarget;
		if (target == null) {
			await use(null);
			return;
		}
		const started = await startSuiteTarget({ target, variant, tls: tls(), testInfo });
		// the OP under test is the emulated OP: discovered at its server (it replaces the config's server.discoveryUrl)
		conformance.config.server = { ...conformance.config.server, discoveryUrl: started.discoveryUrl };
		try {
			await use(started);
		} finally {
			await started.close();
		}
	},

	// the emulated OP (suite-vs-suite) must be up before discovery
	registrationOp: async ({ conformance, variant, suiteTarget: _suiteTarget }, use) => {
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
		await use({
			testName,
			testId: log.testId,
			config,
			variant,
			metadata,
			baseUrl: server.baseUrl,
			redirectUri,
			server,
			browser,
			log,
		});
	},

	op: async ({ registrationOp }, use) => {
		discovery.extractTLSTestValuesFromServerConfiguration(registrationOp.metadata);
		const jwks = await loadServerKeys(registrationOp.metadata);
		await use({ ...registrationOp, jwks });
	},

	// the OP without keys is enough to register a client, so modules on `registrationOp` can configure clients too
	configureClient: async ({ registrationOp: op }, use) => {
		const configured: { registered: RegisteredClient; setup: ClientSetup }[] = [];
		try {
			await use(async (setup = {}) => {
				const registered = await setUpClient(op, setup);
				configured.push({ registered, setup });
				return registered;
			});
		} finally {
			for (const { registered, setup } of configured) {
				await tearDownClient(registered, setup);
			}
		}
	},

	rp: async ({ conformance, variant, suite }, use, testInfo) => {
		const rp = createRp({
			testName: conformance.testName,
			variant: variant as unknown as RpVariant,
			config: conformance.config,
			server: conformance.server,
			log: conformance.log,
			clientDriver: suite.loaded.clientDriver,
			browser: conformance.browser,
			skip: (reason) => {
				testInfo.skip(true, reason);
				throw new Error("unreachable: testInfo.skip throws");
			},
		});
		try {
			await use(rp);
		} finally {
			await rp.close();
		}
	},

	// the OP (and its keys) is set up before the client, as upstream's configure does
	client: async ({ op: _op, configureClient }, use) => {
		await use(await configureClient());
	},

	client2: async ({ op: _op, configureClient }, use) => {
		await use(await configureClient({ configKey: "client2" }));
	},
});

/**
 * Registers (or takes from the configuration) the client and makes sure the OP supports the variant's client
 * authentication.
 *
 * upstream: AbstractOIDCCServerTest.configureClient / completeClientConfiguration (AbstractOIDCCMultipleClient for
 * client2; AbstractOIDCCDynamicRegistrationTest.configureDynamicClient with `checkClientAuthSupported: false`)
 */
async function setUpClient(op: RegistrationOp, setup: ClientSetup): Promise<RegisteredClient> {
	const configKey = setup.configKey ?? "client";
	let registered: RegisteredClient;
	if (op.variant.client_registration === "static_client") {
		const client = registration.getStaticClientConfiguration(op.config, setup.staticConfigKey ?? configKey);
		registered = { client, keys: registration.configureStaticClientKeys(client), dynamic: false };
	} else {
		registered = await registration.registerClient({
			testId: op.testId,
			metadata: op.metadata,
			config: op.config,
			configKey,
			responseType: op.variant.response_type,
			clientAuthType: op.variant.client_auth_type,
			redirectUri: setup.redirectUri ?? op.redirectUri,
			generateKeys: setup.generateKeys,
			jwksUri: setup.jwksUri,
			customize: setup.customize,
		});
	}
	if (setup.completeClientConfiguration) {
		setup.completeClientConfiguration(op, registered.client);
	} else {
		registration.setScopeInClientConfigurationToOpenId(registered.client);
	}
	if (op.variant.server_metadata === "discovery" && setup.checkClientAuthSupported !== false) {
		soft(() => discovery.ensureServerConfigurationSupportsClientAuth(op.metadata, op.variant.client_auth_type));
	}
	return registered;
}

/** upstream: AbstractOIDCCServerTest.unregisterClient (AbstractOIDCCMultipleClient.cleanup for client2) */
async function tearDownClient(registered: RegisteredClient, setup: ClientSetup): Promise<void> {
	if (registered.dynamic) {
		// upstream's multiple client modules prefix the blocks of the second client
		const prefix = setup.configKey === "client2" ? "Second client: " : "";
		await block(prefix + "Unregister dynamically registered client", () =>
			soft(() => registration.unregisterDynamicallyRegisteredClient(registered.client), "warning"),
		);
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
