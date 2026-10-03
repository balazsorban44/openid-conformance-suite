import { defineConfig } from "vitest/config";

/** Unit tests for the helpers (`src/**\/*.test.ts`); conformance tests are Playwright specs under tests/. */
export default defineConfig({
	test: {
		include: ["src/**/*.test.ts", "scripts/**/*.test.ts"],
		environment: "node",
	},
});
