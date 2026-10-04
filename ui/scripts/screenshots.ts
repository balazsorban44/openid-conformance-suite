/**
 * Screenshots of the UI for ui/README.md (ui/docs/*.png), light and dark, 1440x900:
 *
 *   node scripts/screenshots.ts [--url http://127.0.0.1:3000] [--start op-dynamic] [--out docs]
 *
 * The UI must be running (`pnpm ui`). With --start, a run of that CI project is started first and shot while it is
 * in progress; the script then waits for it to end so the module pages show its logs. The module pages are the
 * newest module with a failure in its log and the newest with screenshots, found in the results directory.
 */
import { chromium, type Page } from "@playwright/test";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values: args } = parseArgs({
	options: {
		url: { type: "string", default: "http://127.0.0.1:3000" },
		start: { type: "string" },
		out: { type: "string", default: resolve(import.meta.dirname, "..", "docs") },
		results: { type: "string", default: resolve(import.meta.dirname, "..", "..", "test-results") },
	},
});
const base = args.url.replace(/\/$/, "");
const themes = ["light", "dark"] as const;

interface ModuleReport {
	testId: string;
	analysis: { expected_failures: unknown[]; unexpected_failures: unknown[] };
}

/** The module-report.json files under the results directory, newest first, with their directory's file names */
async function moduleReports(): Promise<{ report: ModuleReport; files: string[]; mtime: number }[]> {
	const found: { report: ModuleReport; files: string[]; mtime: number }[] = [];
	const visit = async (dir: string, depth: number): Promise<void> => {
		const files = await readdir(dir).catch(() => [] as string[]);
		if (files.includes("module-report.json")) {
			const file = join(dir, "module-report.json");
			found.push({
				report: JSON.parse(await readFile(file, "utf8")) as ModuleReport,
				files,
				mtime: (await stat(file)).mtimeMs,
			});
			return;
		}
		if (depth < 3) {
			for (const f of files) {
				if (f !== "attachments" && (await stat(join(dir, f))).isDirectory()) {
					await visit(join(dir, f), depth + 1);
				}
			}
		}
	};
	await visit(args.results, 0);
	return found.sort((a, b) => b.mtime - a.mtime);
}

async function shoot(page: Page, path: string, name: string, prepare?: (page: Page) => Promise<void>): Promise<void> {
	for (const theme of themes) {
		await page.emulateMedia({ colorScheme: theme });
		await page.goto(base + path, { waitUntil: "networkidle" });
		await prepare?.(page);
		await page.waitForTimeout(400);
		const file = join(args.out, `${name}-${theme}.png`);
		await page.screenshot({ path: file });
		console.log(`${file} (${Math.round((await stat(file)).size / 1024)} KB)`);
	}
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
	const res = await fetch(base + path, init);
	const body = (await res.json()) as T & { error?: string };
	if (!res.ok) {
		throw new Error(`${path}: ${body.error ?? res.status}`);
	}
	return body;
}

interface Runs {
	active: string | null;
	runs: { id: string; endedAt?: number; modules: { state: string }[] }[];
}

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });

if (args.start) {
	const { run } = await api<{ run: { id: string } }>("/api/runs", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ kind: "project", project: args.start, options: { verbose: true } }),
	});
	// a run in progress: a few modules done, the next one running
	for (;;) {
		const { runs } = await api<Runs>("/api/runs");
		const r = runs.find((x) => x.id === run.id);
		if (!r || r.endedAt || r.modules.filter((m) => m.state === "done").length >= 6) {
			break;
		}
		await new Promise((done) => setTimeout(done, 1000));
	}
	await shoot(page, `/runs/${run.id}`, "run-live");
	for (;;) {
		const { active } = await api<Runs>("/api/runs");
		if (active !== run.id) {
			break;
		}
		await new Promise((done) => setTimeout(done, 2000));
	}
}

await shoot(page, "/", "overview");
await shoot(page, "/", "run-dialog", async (p) => {
	await p.getByRole("button", { name: "New run" }).first().click();
	await p.getByRole("dialog").waitFor();
});

const reports = await moduleReports();
const failure = reports.find(
	(r) => r.report.analysis.unexpected_failures.length + r.report.analysis.expected_failures.length > 0,
);
if (failure) {
	await shoot(page, `/modules/${failure.report.testId}`, "module-failure", async (p) => {
		// the failing entry, highlighted in the log
		await p.getByRole("link", { name: "Show in log" }).first().click();
		await p.locator(":target").evaluate((el) => el.scrollIntoView({ block: "center" }));
	});
}
const withScreenshots = reports.find((r) => r.files.some((f) => f.startsWith("placeholder-") && f.endsWith(".png")));
if (withScreenshots) {
	await shoot(page, `/modules/${withScreenshots.report.testId}`, "module-screenshots", async (p) => {
		await p.getByText("Screenshots", { exact: true }).scrollIntoViewIfNeeded();
		await p.evaluate(() => window.scrollBy(0, -120));
	});
}

await browser.close();
