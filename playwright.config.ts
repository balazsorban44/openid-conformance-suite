import { defineConfig } from "@playwright/test";

/**
 * tests/plan.spec.ts generates one test per module instance of the selected plan. The plan is selected with the
 * CONFORMANCE_* environment variables, or CONFORMANCE_PROJECT=<name from src/runner/projects.ts> (the CLI
 * `openid-conformance run` / `openid-conformance ci` set these). See .claude/skills/run-conformance.
 */
export default defineConfig({
	testDir: "./tests",
	// modules of one plan run serially (they share the implementation under test); projects can run in parallel
	fullyParallel: false,
	workers: Number(process.env["CONFORMANCE_WORKERS"] ?? 1),
	retries: 0,
	timeout: Number(process.env["CONFORMANCE_TEST_TIMEOUT"] ?? 240_000),
	expect: { timeout: 10_000 },
	reporter: [
		["list"],
		["html", { open: "never", outputFolder: process.env["PLAYWRIGHT_HTML_OUTPUT_DIR"] ?? "playwright-report" }],
		["github"],
		["./src/runner/reporter.ts"],
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
	projects: [{ name: process.env["CONFORMANCE_PROJECT"] ?? "conformance", testMatch: /plan\.spec\.ts/ }],
});
