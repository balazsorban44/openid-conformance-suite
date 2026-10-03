import { defineConfig } from "@playwright/test";
import { portedPlans, projects } from "./src/runner/projects.ts";
import { globBody } from "./src/suite/config.ts";

/**
 * What runs is selected with the CONFORMANCE_* environment (the CLI `openid-conformance run` / `ci` sets it, see
 * .claude/skills/run-conformance):
 *
 *   CONFORMANCE_PROJECT   a project from src/runner/projects.ts (plan, variant, config), or
 *   CONFORMANCE_PLAN + CONFORMANCE_CONFIG (+ CONFORMANCE_VARIANT)
 *   CONFORMANCE_MODULE    only modules whose name matches this glob
 *
 * A plan's rewritten modules run from its spec file (portedPlans), the rest from tests/plan.spec.ts (the old
 * framework). Without a selection only tests/plan.spec.ts is matched, which then skips with a hint.
 */
const project = projects.find((p) => p.name === process.env["CONFORMANCE_PROJECT"]);
const plan = process.env["CONFORMANCE_PLAN"] ?? project?.plan;
const configured = Boolean(process.env["CONFORMANCE_CONFIG"] ?? project?.config);
const specs =
	configured && !project?.legacy
		? Object.entries(portedPlans)
				.filter(([name]) => !plan || name === plan)
				.map(([, p]) => p.spec)
		: [];
const moduleGlob = process.env["CONFORMANCE_MODULE"];

export default defineConfig({
	testDir: "./tests",
	// modules of one plan run serially (they share the implementation under test); projects can run in parallel
	fullyParallel: false,
	workers: Number(process.env["CONFORMANCE_WORKERS"] ?? 1),
	retries: 0,
	timeout: Number(process.env["CONFORMANCE_TEST_TIMEOUT"] ?? 240_000),
	expect: { timeout: 10_000 },
	// module titles are "<module>: ..." (tests/op, tests/rp) or "<module>[variant]" (tests/plan.spec.ts)
	grep: moduleGlob ? new RegExp(`(^|\\s)(${globBody(moduleGlob)})(:|\\[)`) : undefined,
	reporter: [
		["list"],
		["html", { open: "never", outputFolder: process.env["PLAYWRIGHT_HTML_OUTPUT_DIR"] ?? "playwright-report" }],
		["github"],
		["./src/suite/report.ts"],
	],
	outputDir: process.env["PLAYWRIGHT_TEST_OUTPUT_DIR"] ?? "test-results",
	use: {
		headless: true,
		screenshot: "only-on-failure",
		video: process.env["CONFORMANCE_VIDEO"] === "off" ? "off" : "retain-on-failure",
		trace: process.env["CONFORMANCE_TRACE"] === "on" ? "on" : "retain-on-failure",
		ignoreHTTPSErrors: true,
		actionTimeout: 15_000,
		navigationTimeout: 30_000,
	},
	projects: [
		{
			name: process.env["CONFORMANCE_PROJECT"] ?? "conformance",
			testMatch: ["plan.spec.ts", ...specs].map(
				(s) => new RegExp(s.replace(/^tests\//, "").replace(/[.]/g, "\\.") + "$"),
			),
		},
	],
});
