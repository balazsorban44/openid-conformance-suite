/**
 * suite-vs-suite: the OP tests of this suite run against this suite's own emulated OP (the RP tests' OP, src/rp),
 * selected by the configuration's `suite_target`:
 *
 *   "suite_target": {
 *     "module": "oidcc-client-test",          // the RP test module whose emulated OP serves (tests/rp/shared.ts)
 *     "alias": "emulated-op",                 // its base url: /test/a/emulated-op on a server of its own
 *     "variant": { "request_type": "plain_http_request", "client_registration": "dynamic_client" },
 *     "config": { "waitTimeoutSeconds": 10 }  // the emulated module's configuration
 *   }
 *
 * Per OP test, the `suiteTarget` fixture starts the emulated OP on a second suite server with an event log of its
 * own, and the `op` fixture discovers it (`server.discoveryUrl`). The emulated OP serves any number of flows (a
 * second authorization, a second userinfo call) until the test ends; its checks go to its own log, attached as
 * emulated-op-log.json / emulated-op-log.html, which is not part of the module's expected-failures analysis.
 */
import type { TestInfo } from "@playwright/test";
import { writeFileSync } from "node:fs";
import { startEmulatedOp, type EmulatedOp, type RpVariant } from "../src/rp/op.ts";
import type { SuiteTargetConfig, TestConfig } from "../src/suite/config.ts";
import { createLog, renderLogHtml, resultOf, withContext, type EventLog } from "../src/suite/log.ts";
import { startServer, type TestServer } from "../src/suite/server.ts";
import { emulatedOpModules } from "./rp/shared.ts";

/** The variant parameters of the RP test modules (the @VariantParameters of AbstractOIDCCClientTest) */
const RP_VARIANT_PARAMETERS = [
	"client_registration",
	"client_auth_type",
	"response_type",
	"response_mode",
	"request_type",
] as const;

export interface SuiteTarget {
	/** The emulated OP's name: the RP test module it is (`suite_target.module`) */
	readonly testName: string;
	readonly op: EmulatedOp;
	readonly log: EventLog;
	readonly server: TestServer;
	/** Where the OP test discovers it (the module's `server.discoveryUrl`) */
	readonly discoveryUrl: string;
	/** Stops serving and attaches the emulated OP's log to the test */
	close(): Promise<void>;
}

/**
 * Starts the emulated OP named by `target` for one OP test: `target.variant` wins, the parameters it leaves out
 * (client_auth_type, response_type, response_mode) follow the variant of the module under test, so both sides agree.
 * Its setup checks and the checks on every request it serves are logged into its own log.
 */
export async function startSuiteTarget(args: {
	target: SuiteTargetConfig;
	/** The variant of the OP test */
	variant: Record<string, string>;
	tls: { cert: string; key: string } | undefined;
	testInfo: TestInfo;
}): Promise<SuiteTarget> {
	const { target, testInfo } = args;
	const options = emulatedOpModules[target.module];
	if (!options) {
		const known = Object.keys(emulatedOpModules).join(", ");
		throw new Error(`suite_target.module '${target.module}' is not an emulated OP module (known: ${known})`);
	}
	const variant: Record<string, string> = {};
	for (const name of RP_VARIANT_PARAMETERS) {
		const value = target.variant?.[name] ?? args.variant[name];
		if (value !== undefined) {
			variant[name] = value;
		}
	}
	const testName = target.module;
	const config = structuredClone(target.config ?? {}) as TestConfig;
	const alias = target.alias ?? "emulated-op";
	const log = createLog();
	const server = await startServer({ log, testName, alias, tls: args.tls });
	const close = async () => {
		await server.close();
		await attachLog(testInfo, testName, log, variant);
	};
	log.log("TEST-RUNNER", {
		msg: "Emulated OP test instance " + log.testId + " created",
		result: "INFO",
		baseUrl: server.baseUrl,
		config,
		alias,
		testName,
		variant,
	});
	try {
		// its own log and name; the requests it serves keep this context (startEmulatedOp), outside the test's steps
		const op = await withContext({ log, testName, severity: "failure", step: (_name, fn) => fn() }, () =>
			startEmulatedOp(server, { testName, variant: variant as RpVariant, config }, options()),
		);
		const discoveryUrl = server.baseUrl + "/.well-known/openid-configuration";
		return { testName, op, log, server, discoveryUrl, close };
	} catch (e) {
		await close();
		throw e;
	}
}

/** emulated-op-log.json / emulated-op-log.html next to the module's log */
async function attachLog(
	testInfo: TestInfo,
	testName: string,
	log: EventLog,
	variant: Record<string, string>,
): Promise<void> {
	const attach = async (name: string, body: string, contentType: string) => {
		const path = testInfo.outputPath(name);
		writeFileSync(path, body);
		await testInfo.attach(name, { path, contentType });
	};
	await attach("emulated-op-log.json", JSON.stringify(log.entries, null, 2), "application/json");
	const title = `${testName} (the emulated OP of ${testInfo.title.split(":")[0]})`;
	const html = renderLogHtml(title, log.entries, { result: resultOf(log.entries), status: "FINISHED", variant });
	await attach("emulated-op-log.html", html, "text/html");
}
