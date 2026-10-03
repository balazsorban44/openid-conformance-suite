import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";
import { simpleMatch } from "./browser.ts";
import { globBody, loadConfig, moduleConfig, substitute } from "./config.ts";

test("substitute replaces ${NAME} in every string and keeps functions", () => {
	const hook = async () => {};
	expect(
		substitute(
			{ a: "${TARGET_URL}/x", b: ["${PORT}", 1, null], c: { d: "${UNKNOWN}" }, browser: hook },
			{ TARGET_URL: "https://localhost:1234", PORT: "1234" },
		),
	).toEqual({ a: "https://localhost:1234/x", b: ["1234", 1, null], c: { d: "${UNKNOWN}" }, browser: hook });
});

test("loadConfig splits the runner keys off and reads the expected lists relative to the config", async () => {
	const dir = await mkdtemp(join(tmpdir(), "conformance-config-"));
	await writeFile(join(dir, "ef.json"), JSON.stringify([{ "test-name": "x", condition: "C" }]));
	await writeFile(
		join(dir, "c.json"),
		JSON.stringify({
			alias: "a",
			server: { discoveryUrl: "${TARGET_URL}/.well-known/openid-configuration" },
			target: { command: "node x.ts", url: "https://localhost:${PORT}", readyUrl: "${TARGET_URL}/" },
			expectedFailures: "ef.json",
		}),
	);
	const loaded = await loadConfig(join(dir, "c.json"), undefined, { TARGET_URL: "https://localhost:9", PORT: "9" });
	expect(loaded.config).toEqual({
		alias: "a",
		server: { discoveryUrl: "https://localhost:9/.well-known/openid-configuration" },
	});
	expect(loaded.target).toEqual({ command: "node x.ts", url: "https://localhost:9", readyUrl: "https://localhost:9/" });
	expect(loaded.expectedFailures).toEqual([{ "test-name": "x", condition: "C" }]);
	expect(loaded.filename).toBe("c.json");
});

test("moduleConfig applies `override` for the module (upstream DBTestPlanService.getModuleConfig)", () => {
	const config = { alias: "a", browser: [{ match: "1" }], override: { "oidcc-x": { browser: [{ match: "2" }] } } };
	expect(moduleConfig(config, "oidcc-x")).toEqual({ alias: "a", browser: [{ match: "2" }] });
	expect(moduleConfig(config, "oidcc-y")).toEqual({ alias: "a", browser: [{ match: "1" }] });
});

test("globs and Spring's simpleMatch", () => {
	expect(new RegExp(`^${globBody("oidcc-*")}$`).test("oidcc-server")).toBe(true);
	expect(simpleMatch("https://op/auth*", "https://op/auth?x=1")).toBe(true);
	expect(simpleMatch("*/test/*/callback*", "https://s:1/test/a/x/callback?code=1")).toBe(true);
	expect(simpleMatch("https://op/auth", "https://op/auth?x")).toBe(false);
});
