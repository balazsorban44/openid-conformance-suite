import { test, expect, type BrowserContext } from "@playwright/test";
import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { SuiteServer } from "../src/framework/server.ts";
import { VariantSelection } from "../src/framework/variants.ts";
import { VariantService, type PlanModule } from "../src/framework/VariantService.ts";
import { findPlan } from "../src/registry.ts";
import { loadConfig, type LoadedConfig } from "../src/runner/config.ts";
import { analyzeResultLogs } from "../src/runner/expected.ts";
import { renderLogHtml, type ModuleReport } from "../src/runner/report.ts";
import { projects } from "../src/runner/projects.ts";
import { Target } from "../src/runner/target.ts";
import { runModule } from "../src/runner/TestRunner.ts";

/**
 * One Playwright test per test module instance of the selected plan.
 *
 * Selection: a Playwright project from src/runner/projects.ts (`--project=op-basic-static`), or the environment:
 *   CONFORMANCE_PLAN      plan name (e.g. oidcc-basic-certification-test-plan)
 *   CONFORMANCE_VARIANT   [k=v][k2=v2] (user's variant selection)
 *   CONFORMANCE_CONFIG    path to the configuration (JSON or .ts)
 *   CONFORMANCE_MODULE    optional: only run modules whose testName matches this glob
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectName = process.env["CONFORMANCE_PROJECT"];
const project = projectName ? projects.find((p) => p.name === projectName) : undefined;
const planName = process.env["CONFORMANCE_PLAN"] ?? project?.plan;
const variantString = process.env["CONFORMANCE_VARIANT"] ?? project?.variant ?? "";
const configPath = process.env["CONFORMANCE_CONFIG"] ?? project?.config;
const moduleFilter = process.env["CONFORMANCE_MODULE"];
const skipModules = project?.skipModules ?? [];

if (!planName || !configPath) {
	test("conformance plan selection", () => {
		test.skip(true, "Set CONFORMANCE_PLAN and CONFORMANCE_CONFIG (or select a project) to run a plan");
	});
} else {
	const planClass = findPlan(planName);
	if (!planClass) {
		throw new Error(`Unknown test plan '${planName}'`);
	}
	const selection = VariantSelection.fromBracketString(variantString);
	let modules: PlanModule[] = VariantService.expandPlan(planClass, selection);
	if (moduleFilter) {
		const re = new RegExp("^" + moduleFilter.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");
		modules = modules.filter((m) => re.test(m.testName));
	}

	let loaded: LoadedConfig;
	let server: SuiteServer;
	let target: Target | null = null;

	test.describe(planName, () => {
		// sequential (single worker) but independent: a failing module must not skip the rest of the plan
		test.describe.configure({ mode: "default" });

		test.beforeAll(async () => {
			loaded = await loadConfig(resolve(configPath));
			if (loaded.target) {
				target = new Target(loaded.target);
				await target.start();
			}
			// CONFORMANCE_TLS=1 serves the suite over https with the bundled localhost certificate (or
			// CONFORMANCE_TLS_CERT / CONFORMANCE_TLS_KEY); the specs require https for several suite-hosted URLs
			const tls =
				process.env["CONFORMANCE_TLS"] && process.env["CONFORMANCE_TLS"] !== "0"
					? {
							cert: readFileSync(
								process.env["CONFORMANCE_TLS_CERT"] ?? resolve(__dirname, "../configs/certs/localhost.crt"),
								"utf8",
							),
							key: readFileSync(
								process.env["CONFORMANCE_TLS_KEY"] ?? resolve(__dirname, "../configs/certs/localhost.key"),
								"utf8",
							),
						}
					: undefined;
			server = new SuiteServer({
				port: Number(process.env["CONFORMANCE_PORT"] ?? 0),
				host: process.env["CONFORMANCE_HOST"],
				externalUrl: process.env["CONFORMANCE_EXTERNAL_URL"],
				tls,
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
				test.skip(skipModules.includes(m.testName), "skipped in this CI project");
				testInfo.annotations.push({ type: "plan", description: planName });
				testInfo.annotations.push({ type: "variant", description: vs });

				const run = await runModule({
					moduleClass: m.moduleClass,
					variant: m.variant,
					loaded,
					server,
					context: context as BrowserContext,
					timeoutSeconds: Number(process.env["CONFORMANCE_MODULE_TIMEOUT"] ?? 150),
					onLog: process.env["CONFORMANCE_VERBOSE"]
						? (e) => {
								const extra = ["url", "match", "error", "request_uri", "response_status_code"]
									.filter((k) => e[k] != null)
									.map((k) => `${k}=${String(e[k])}`)
									.join(" ");
								process.stdout.write(
									`${e.src}: ${String(e["msg"] ?? "")} ${e["result"] ? `[${String(e["result"])}]` : ""} ${extra}\n`,
								);
							}
						: undefined,
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

				await testInfo.attach("log.json", {
					body: JSON.stringify(run.entries, null, 2),
					contentType: "application/json",
				});
				await testInfo.attach("log.html", {
					body: renderLogHtml(title, run.entries, { result: run.result, status: run.status, variant: run.variant }),
					contentType: "text/html",
				});
				if (run.nested) {
					await testInfo.attach("emulated-op-log.html", {
						body: renderLogHtml(`${title} (emulated OP: ${run.nested.testName})`, run.nested.entries, {
							result: run.nested.result,
							status: run.nested.status,
							variant: {},
						}),
						contentType: "text/html",
					});
				}
				for (const s of run.screenshots) {
					await testInfo.attach(s.name + ".png", { body: s.png, contentType: "image/png" });
				}
				await testInfo.attach("module-report.json", { body: JSON.stringify(report), contentType: "application/json" });
				if (target && target.output.length > 0) {
					await testInfo.attach("target-output.txt", { body: target.output.join(""), contentType: "text/plain" });
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

				const problems: string[] = [];
				for (const f of analysis.unexpected_failures) {
					problems.push(`FAILURE ${f.src}${f.current_block ? ` [${f.current_block}]` : ""}: ${f.msg ?? ""}`);
				}
				for (const f of analysis.unexpected_warnings) {
					problems.push(`WARNING ${f.src}: ${f.msg ?? ""}`);
				}
				for (const f of analysis.expected_failures_did_not_happen) {
					problems.push(`expected failure did not happen: ${f.src}`);
				}
				for (const f of analysis.expected_warnings_did_not_happen) {
					problems.push(`expected warning did not happen: ${f.src}`);
				}
				if (analysis.unexpected_skip) {
					problems.push("module was unexpectedly SKIPPED");
				}
				if (analysis.expected_skip_did_not_happen) {
					problems.push("module was expected to be skipped but completed");
				}
				if (run.status === "INTERRUPTED") {
					const last = [...run.entries]
						.reverse()
						.find((e) => e["result"] === "INTERRUPTED" || e["result"] === "FAILURE");
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

export function configExists(p: string): boolean {
	return existsSync(p);
}
