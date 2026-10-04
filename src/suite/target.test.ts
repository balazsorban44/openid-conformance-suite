import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { startTarget } from "./target.ts";

/** A target that fails its first start (like a port another worker took) and serves /ready from the second */
function flakyTarget(): { command: string; readyUrl: string } {
	const dir = mkdtempSync(join(tmpdir(), "target-"));
	const script = join(dir, "target.cjs");
	writeFileSync(
		script,
		`const fs = require("node:fs");
const marker = ${JSON.stringify(join(dir, "started-once"))};
if (!fs.existsSync(marker)) { fs.writeFileSync(marker, ""); console.error("listen EADDRINUSE"); process.exit(1); }
require("node:http").createServer((req, res) => res.end("ok")).listen(Number(process.env.PORT), "127.0.0.1");`,
	);
	return { command: `node ${script}`, readyUrl: "http://127.0.0.1:${PORT}/ready" };
}

describe("startTarget", () => {
	it("retries with a new port when the target exits before it is ready", async () => {
		const target = await startTarget({ ...flakyTarget(), url: "http://127.0.0.1:${PORT}" });
		try {
			expect(target.port).toBeGreaterThan(0);
			expect(target.url).toBe(`http://127.0.0.1:${target.port}`);
		} finally {
			await target.stop();
		}
	});

	it("gives up after the configured attempts", async () => {
		const dir = mkdtempSync(join(tmpdir(), "target-"));
		const script = join(dir, "exit.cjs");
		writeFileSync(script, "process.exit(1);");
		await expect(
			startTarget({ command: `node ${script}`, readyUrl: "http://127.0.0.1:${PORT}/ready" }, process.cwd(), 2),
		).rejects.toThrow(/exited with code 1/);
	});
});
