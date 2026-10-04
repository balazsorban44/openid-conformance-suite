import { defineConfig, devices, type PlaywrightTestOptions, type PlaywrightWorkerOptions } from "@playwright/test";
import {
	browsers,
	DEFAULT_BROWSER,
	isBrowserName,
	plans,
	projects,
	runName,
	type BrowserName,
} from "./src/runner/projects.ts";
import { globBody } from "./src/suite/config.ts";

/**
 * What runs is selected with the CONFORMANCE_* environment (the CLI `openid-conformance run` / `ci` sets it, see
 * .claude/skills/run-conformance):
 *
 *   CONFORMANCE_PROJECT   a project from src/runner/projects.ts (plan, variant, config), or
 *   CONFORMANCE_PLAN + CONFORMANCE_CONFIG (+ CONFORMANCE_VARIANT)
 *   CONFORMANCE_MODULE    only modules whose name matches this glob
 *   CONFORMANCE_BROWSER   the browser the suite drives: chromium (default), firefox, webkit, chrome-mobile
 *
 * The selected plan runs from its spec file (`plans` in src/runner/projects.ts). Without a plan every spec file is
 * matched (so `playwright test --list` and editors see every test); running them needs a configuration.
 */
const project = projects.find((p) => p.name === process.env["CONFORMANCE_PROJECT"]);
const planName = process.env["CONFORMANCE_PLAN"] ?? project?.plan;
if (planName && !plans[planName]) {
	throw new Error(`Unknown test plan '${planName}' (see \`openid-conformance list\`)`);
}
const specs = [...new Set(planName ? [plans[planName].spec] : Object.values(plans).map((p) => p.spec))];
const moduleGlob = process.env["CONFORMANCE_MODULE"];
const browser = process.env["CONFORMANCE_BROWSER"] || DEFAULT_BROWSER;
if (!isBrowserName(browser)) {
	throw new Error(`Unknown CONFORMANCE_BROWSER '${browser}'; known: ${browsers.join(", ")}`);
}

/**
 * The Playwright project's `use` for each browser. chromium stays Playwright's plain default (the headless shell,
 * 1280x720, its own user agent); the others are Playwright's device descriptors.
 */
const BROWSER_USE: Record<BrowserName, Partial<PlaywrightTestOptions & PlaywrightWorkerOptions>> = {
	chromium: { browserName: "chromium" },
	firefox: { ...devices["Desktop Firefox"], browserName: "firefox" },
	webkit: { ...devices["Desktop Safari"], browserName: "webkit" },
	"chrome-mobile": { ...devices["Pixel 7"], browserName: "chromium" },
};

export default defineConfig({
	testDir: "./tests",
	// modules of one plan run serially (they share the implementation under test); projects can run in parallel
	fullyParallel: false,
	workers: Number(process.env["CONFORMANCE_WORKERS"] ?? 1),
	retries: 0,
	timeout: Number(process.env["CONFORMANCE_TEST_TIMEOUT"] ?? 240_000),
	expect: { timeout: 10_000 },
	// test titles are "<module>: <what the OP/RP must do>"
	grep: moduleGlob ? new RegExp(`(^|\\s)(${globBody(moduleGlob)}):`) : undefined,
	// ./src/suite/report.ts: the console output (a line per module, the failures), conformance-report/, the GitHub
	// step summary and annotations; the HTML report is the record with the logs, screenshots and videos
	reporter: [
		["./src/suite/report.ts"],
		["html", { open: "never", outputFolder: process.env["PLAYWRIGHT_HTML_OUTPUT_DIR"] ?? "playwright-report" }],
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
			// "<project>-<browser>" for the browsers other than chromium, so reports and artifacts tell them apart
			name: runName(process.env["CONFORMANCE_PROJECT"] ?? "conformance", browser),
			use: BROWSER_USE[browser],
			testMatch: specs.map((s) => new RegExp(s.replace(/^tests\//, "").replace(/[.]/g, "\\.") + "$")),
		},
	],
});
