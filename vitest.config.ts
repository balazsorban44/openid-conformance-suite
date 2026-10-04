import { defineConfig } from "vitest/config";

/** Unit tests for the helpers (`src/**\/*.test.ts`); conformance tests are Playwright specs under tests/. */
export default defineConfig({
	test: {
		include: ["src/**/*.test.ts", "scripts/**/*.test.ts"],
		environment: "node",
		// On GitHub Actions keep the reporter's annotations but not its "Vitest Test Report" job summary: the workflow
		// run page shows the conformance runs only.
		reporters: process.env["GITHUB_ACTIONS"]
			? ["default", ["github-actions", { jobSummary: { enabled: false } }]]
			: ["default"],
	},
});
