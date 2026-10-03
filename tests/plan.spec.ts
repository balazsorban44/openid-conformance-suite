import { test, expect } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { LogEntry } from "../src/framework/EventLog.ts";
import { SuiteServer } from "../src/framework/server.ts";
import { VariantSelection } from "../src/framework/variants.ts";
import { expandPlan } from "../src/framework/VariantService.ts";
import { findPlan } from "../src/registry.ts";
import { loadConfig, type LoadedConfig } from "../src/runner/config.ts";
import { analyzeResultLogs, describeProblems } from "../src/runner/expected.ts";
import { globToRegExp } from "../src/runner/glob.ts";
import { renderLogHtml, type ModuleReport } from "../src/runner/report.ts";
import { projects } from "../src/runner/projects.ts";
import { Target } from "../src/runner/target.ts";
import { runModule } from "../src/runner/TestRunner.ts";

/**
 * One Playwright test per test module instance of the selected plan.
 *
 * Selection: CONFORMANCE_PROJECT=<name from src/runner/projects.ts> (`openid-conformance ci --project op-basic-static`
 * sets it and names the Playwright project after it), or the environment:
 *   CONFORMANCE_PLAN      plan name (e.g. oidcc-basic-certification-test-plan)
 *   CONFORMANCE_VARIANT   [k=v][k2=v2] (user's variant selection)
 *   CONFORMANCE_CONFIG    path to the configuration (JSON or .ts)
 *   CONFORMANCE_MODULE    optional: only run modules whose testName matches this glob
 */

const projectName = process.env["CONFORMANCE_PROJECT"];
const project = projectName ? projects.find((p) => p.name === projectName) : undefined;
const planName = process.env["CONFORMANCE_PLAN"] ?? project?.plan;
const variantString = process.env["CONFORMANCE_VARIANT"] ?? project?.variant ?? "";
const configPath = process.env["CONFORMANCE_CONFIG"] ?? project?.config;
const moduleFilter = process.env["CONFORMANCE_MODULE"];
const skipModules = project?.skipModules ?? {};

if (!planName || !configPath) {
	test("conformance plan selection", () => {
		test.skip(true, "Set CONFORMANCE_PLAN and CONFORMANCE_CONFIG (or select a project) to run a plan");
	});
} else {
	const planClass = findPlan(planName);
	if (!planClass) {
		throw new Error(`Unknown test plan '${planName}'`);
	}
	const moduleRe = moduleFilter ? globToRegExp(moduleFilter) : null;
	const modules = expandPlan(planClass, VariantSelection.fromBracketString(variantString)).filter(
		(m) => !moduleRe || moduleRe.test(m.testName),
	);

	let loaded: LoadedConfig;
	let server: SuiteServer;
	let target: Target | null = null;

	test.describe(planName, () => {
		// sequential (single worker) but independent: a failing module must not skip the rest of the plan
		test.describe.configure({ mode: "default" });

		test.beforeAll(async () => {
			loaded = await loadConfig(resolve(configPath));
			if (loaded.target) {
				target = new Target(loaded.target, process.env["CONFORMANCE_CWD"] ?? process.cwd());
				await target.start();
			}
			server = new SuiteServer({
				port: Number(process.env["CONFORMANCE_PORT"] ?? 0),
				host: process.env["CONFORMANCE_HOST"],
				externalUrl: process.env["CONFORMANCE_EXTERNAL_URL"],
				tls: loadTls(),
			});
			await server.start();
		});

		test.afterAll(async () => {
			await server?.stop();
			if (!process.env["CONFORMANCE_KEEP_SERVER"]) {
				await target?.stop();
			}
		});

		for (const m of modules) {
			const vs = m.variant.toBracketString();
			const title = `${m.testName}${vs}`;
			test(title, async ({ context }, testInfo) => {
				test.skip(m.testName in skipModules, skipModules[m.testName]);
				testInfo.annotations.push({ type: "plan", description: planName });
				testInfo.annotations.push({ type: "variant", description: vs });

				const run = await runModule({
					moduleClass: m.moduleClass,
					variant: m.variant,
					loaded,
					server,
					context,
					timeoutSeconds: Number(process.env["CONFORMANCE_MODULE_TIMEOUT"] ?? 150),
					onLog: process.env["CONFORMANCE_VERBOSE"] ? printEntry : undefined,
				});

				const analysis = analyzeResultLogs(
					m.testName,
					run.variant,
					run.result,
					run.entries,
					loaded.expectedFailures,
					loaded.expectedSkips,
					loaded.filename,
				);
				const report: ModuleReport = {
					plan: planName,
					testName: m.testName,
					variant: run.variant,
					variantString: vs,
					testId: run.testId,
					status: run.status,
					result: run.result,
					ok: analysis.ok && run.status !== "INTERRUPTED",
					durationMs: run.durationMs,
					analysis,
					title,
				};

				// attachments are written as files into the test's output directory (test-results/<test>/) so they are
				// readable without opening the HTML report, and attached so the report links them too
				const attach = async (name: string, body: string | Buffer, contentType: string) => {
					const path = testInfo.outputPath(name);
					writeFileSync(path, body);
					await testInfo.attach(name, { path, contentType });
				};
				await attach("log.json", JSON.stringify(run.entries, null, 2), "application/json");
				await attach(
					"log.html",
					renderLogHtml(title, run.entries, { result: run.result, status: run.status, variant: run.variant }),
					"text/html",
				);
				if (run.nested) {
					await attach(
						"emulated-op-log.html",
						renderLogHtml(`${title} (emulated OP: ${run.nested.testName})`, run.nested.entries, {
							result: run.nested.result,
							status: run.nested.status,
							variant: {},
						}),
						"text/html",
					);
				}
				for (const s of run.screenshots) {
					await attach(s.name + ".png", s.png, "image/png");
				}
				await attach("module-report.json", JSON.stringify(report), "application/json");
				if (target && target.output.length > 0) {
					await attach("target-output.txt", target.output.join(""), "text/plain");
				}

				for (const f of analysis.expected_failures) {
					testInfo.annotations.push({ type: "expected failure", description: `${f.src}: ${f.msg ?? ""}` });
				}
				for (const f of analysis.unexpected_warnings) {
					testInfo.annotations.push({ type: "warning", description: `${f.src}: ${f.msg ?? ""}` });
				}
				if (run.result === "SKIPPED" && analysis.ok) {
					testInfo.annotations.push({ type: "skipped", description: "test module reported SKIPPED" });
					test.skip(true, "test module reported SKIPPED");
				}

				const problems = describeProblems(analysis);
				if (run.status === "INTERRUPTED") {
					const last = run.entries.findLast((e) => e["result"] === "INTERRUPTED" || e["result"] === "FAILURE");
					problems.push(`module was INTERRUPTED: ${String(last?.["msg"] ?? "")}`);
				}
				expect
					.soft(problems, `${title} (result ${run.result}, status ${run.status}). See the log.html attachment.`)
					.toEqual([]);
				expect(report.ok, `module result ${run.result}`).toBe(true);
			});
		}
	});
}

/**
 * CONFORMANCE_TLS=1 serves the suite over https with the bundled localhost certificate (or CONFORMANCE_TLS_CERT /
 * CONFORMANCE_TLS_KEY); the specs require https for several suite-hosted URLs.
 */
function loadTls(): { cert: string; key: string } | undefined {
	if (!process.env["CONFORMANCE_TLS"] || process.env["CONFORMANCE_TLS"] === "0") {
		return undefined;
	}
	return {
		cert: readPem("CONFORMANCE_TLS_CERT", "localhost.crt"),
		key: readPem("CONFORMANCE_TLS_KEY", "localhost.key"),
	};
}

function readPem(envName: string, bundled: string): string {
	return readFileSync(process.env[envName] ?? resolve(import.meta.dirname, "../configs/certs", bundled), "utf8");
}

/** CONFORMANCE_VERBOSE: stream the event log to the console */
function printEntry(e: LogEntry): void {
	const extra = ["url", "match", "error", "request_uri", "response_status_code"]
		.filter((k) => e[k] != null)
		.map((k) => `${k}=${String(e[k])}`)
		.join(" ");
	process.stdout.write(
		`${e.src}: ${String(e["msg"] ?? "")} ${e["result"] ? `[${String(e["result"])}]` : ""} ${extra}\n`,
	);
}
