#!/usr/bin/env node
/**
 * Compare the ported functions and tests with the upstream Java suite. See .claude/skills/sync-upstream/SKILL.md.
 *
 *   node scripts/sync-upstream.ts --fetch                 clone/update upstream into .upstream/ ($UPSTREAM)
 *   node scripts/sync-upstream.ts [--status]              list ported symbols whose Java source changed since the pin
 *   node scripts/sync-upstream.ts --diff <ts>#<symbol>    git diff of the Java files a function/test ports (pinned..HEAD)
 *   node scripts/sync-upstream.ts --diff <ts path>        the same for every symbol of a TS file
 *   node scripts/sync-upstream.ts --pin                   re-pin commit + blob hashes to upstream HEAD
 *   node scripts/sync-upstream.ts --report <report.md> <body.md>   write the changes as markdown (the weekly sync PR)
 *
 * The lock's `symbols` (Java file -> { blob, loc, ts, symbol }) are maintained by scripts/upstream-lock-symbols.ts
 * from the `upstream:` comments.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { LockFile } from "./upstream-lock-symbols.ts";

const root = resolve(import.meta.dirname, "..");
const lockPath = join(root, "upstream.lock.json");
const upstreamDir = process.env["UPSTREAM"] ?? join(root, ".upstream");

const lock = JSON.parse(readFileSync(lockPath, "utf8")) as LockFile;

function git(args: string[], cwd = upstreamDir): string {
	return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }).trim();
}

function ensureUpstream(): void {
	if (!existsSync(join(upstreamDir, ".git"))) {
		console.error(`upstream checkout not found at ${upstreamDir}; run with --fetch first`);
		process.exit(2);
	}
}

function fetch(): void {
	if (!existsSync(join(upstreamDir, ".git"))) {
		execFileSync("git", ["clone", "--filter=blob:none", lock.upstream.repo, upstreamDir], { stdio: "inherit" });
	} else {
		git(["fetch", "origin", "master"]);
		git(["checkout", "-q", "origin/master"]);
	}
	// make sure the pinned commit is available for diffs
	try {
		git(["cat-file", "-e", lock.upstream.commit + "^{commit}"]);
	} catch {
		git(["fetch", "origin", lock.upstream.commit]);
	}
	console.log(`upstream at ${git(["rev-parse", "HEAD"])} (pinned ${lock.upstream.commit})`);
}

/** The blob of a Java file in the upstream working tree (HEAD of the checkout), null when deleted upstream */
function blobOf(javaPath: string): string | null {
	const p = join(upstreamDir, javaPath);
	return existsSync(p) ? git(["hash-object", p]) : null;
}

function locOf(javaPath: string): number {
	return readFileSync(join(upstreamDir, javaPath), "utf8").split("\n").length;
}

function status(): void {
	ensureUpstream();
	const changed: string[] = [];
	const deleted: string[] = [];
	for (const [java, info] of Object.entries(lock.symbols)) {
		const blob = blobOf(java);
		if (blob === null) {
			deleted.push(`  ${info.ts}#${info.symbol}  <- ${java}`);
		} else if (blob !== info.blob) {
			changed.push(`  ${info.ts}#${info.symbol}  <- ${java}`);
		}
	}
	const total = Object.keys(lock.symbols).length;
	console.log(`upstream HEAD ${git(["rev-parse", "HEAD"])}, pinned ${lock.upstream.commit}`);
	console.log(`unchanged: ${total - changed.length - deleted.length} of ${total}`);
	console.log(`changed: ${changed.length}`);
	for (const line of changed) {
		console.log(line);
	}
	console.log(`deleted upstream: ${deleted.length}`);
	for (const line of deleted) {
		console.log(line);
	}
	process.exitCode = changed.length + deleted.length > 0 ? 1 : 0;
}

function diff(target: string): void {
	ensureUpstream();
	const [path, symbol] = target.split("#");
	const java = Object.entries(lock.symbols)
		.filter(([, s]) => s.ts === path && (symbol === undefined || s.symbol === symbol))
		.map(([j]) => j);
	if (java.length === 0) {
		console.error(`not in lock: ${target}`);
		process.exit(2);
	}
	const out = execFileSync("git", ["diff", lock.upstream.commit, "HEAD", "--", ...java], {
		cwd: upstreamDir,
		encoding: "utf8",
	});
	process.stdout.write(out || "(no changes)\n");
}

/** A ported symbol whose Java source changed (or disappeared) upstream since the pin, with its diff */
export interface ChangedSymbol {
	ts: string;
	symbol: string;
	java: string;
	deleted: boolean;
	/** `git diff --stat`-like counts */
	added: number;
	removed: number;
	/** the unified diff (empty for a deleted file) */
	diff: string;
}

const DIFF_LINES_PER_SYMBOL = 400;

function changedSymbols(): ChangedSymbol[] {
	const out: ChangedSymbol[] = [];
	for (const [java, info] of Object.entries(lock.symbols)) {
		const blob = blobOf(java);
		if (blob === info.blob) {
			continue;
		}
		const patch =
			blob === null
				? ""
				: execFileSync("git", ["diff", lock.upstream.commit, "HEAD", "--", java], {
						cwd: upstreamDir,
						encoding: "utf8",
					});
		const lines = patch.split("\n");
		out.push({
			ts: info.ts,
			symbol: info.symbol,
			java,
			deleted: blob === null,
			added: lines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length,
			removed: lines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length,
			diff: patch,
		});
	}
	return out.sort((a, b) => a.ts.localeCompare(b.ts) || a.symbol.localeCompare(b.symbol));
}

const shortSha = (c: string) => c.slice(0, 12);

/** The weekly sync PR: a full report (every diff) and a short PR body pointing at it */
export function renderReport(
	changes: ChangedSymbol[],
	range: { repo: string; pinned: string; head: string; headDate: string; reportPath: string; reportUrl?: string },
): { report: string; body: string } {
	const web = range.repo.replace(/\.git$/, "");
	const compare = `${web}/-/compare/${range.pinned}...${range.head}`;
	const javaLink = (java: string, deleted: boolean) =>
		deleted
			? `~~${java}~~`
			: `[${java.replace(/^src\/main\/java\/net\/openid\/conformance\//, "")}](${web}/-/blob/${range.head}/${java})`;
	const table = [
		"| Ported in | Upstream file | Change |",
		"|---|---|---|",
		...changes.map(
			(c) =>
				`| \`${c.ts}#${c.symbol}\` | ${javaLink(c.java, c.deleted)} | ${c.deleted ? "deleted upstream" : `+${c.added} −${c.removed}`} |`,
		),
	].join("\n");
	const intro = `Upstream moved from [\`${shortSha(range.pinned)}\`](${web}/-/commit/${range.pinned}) to [\`${shortSha(range.head)}\`](${web}/-/commit/${range.head}) (${range.headDate.slice(0, 10)}, [compare](${compare})). ${changes.length} ported ${changes.length === 1 ? "symbol has" : "symbols have"} upstream changes.`;
	const howTo = [
		"## How to finish this PR",
		"",
		"1. For each row: `pnpm sync-upstream --diff <ts>#<symbol>` shows the Java diff; apply the change to the TypeScript",
		"   function or test (`.claude/skills/writing-tests`, the porting rules), keeping messages, severities and",
		"   requirement tags identical to upstream.",
		"2. `pnpm sync-upstream --pin`, `pnpm lock-symbols`, `pnpm check`, `pnpm test:unit`, and the affected projects",
		"   (`node bin/cli.ts ci --project <name>`).",
		`3. Delete \`${range.reportPath}\` before merging; the weekly sync regenerates it while this PR is open.`,
	].join("\n");
	const body = `${intro}\n\n${table}\n\nThe diffs are in ${range.reportUrl ? `[\`${range.reportPath}\`](${range.reportUrl})` : `\`${range.reportPath}\``} on this branch.\n\n${howTo}`;
	const diffs = changes.map((c) => {
		const lines = c.diff.split("\n");
		const shown = lines.slice(0, DIFF_LINES_PER_SYMBOL).join("\n");
		const cut =
			lines.length > DIFF_LINES_PER_SYMBOL
				? `\n... ${lines.length - DIFF_LINES_PER_SYMBOL} more lines: pnpm sync-upstream --diff ${c.ts}#${c.symbol}`
				: "";
		return `### \`${c.ts}#${c.symbol}\`\n\n${javaLink(c.java, c.deleted)}${c.deleted ? " was deleted upstream." : ""}\n\n${c.deleted ? "" : "```diff\n" + shown + cut + "\n```"}`;
	});
	const md = `# Upstream changes\n\n${intro}\n\n${table}\n\n${diffs.join("\n\n")}\n`;
	return { report: md, body };
}

function report(reportFile: string, bodyFile: string): void {
	ensureUpstream();
	const changes = changedSymbols();
	const head = git(["rev-parse", "HEAD"]);
	const { report: md, body } = renderReport(changes, {
		repo: lock.upstream.repo,
		pinned: lock.upstream.commit,
		head,
		headDate: git(["log", "-1", "--format=%cI"]),
		reportPath: reportFile,
		// on GitHub Actions: the file on the sync branch
		reportUrl: process.env["GITHUB_REPOSITORY"]
			? `${process.env["GITHUB_SERVER_URL"] ?? "https://github.com"}/${process.env["GITHUB_REPOSITORY"]}/blob/sync/upstream/${reportFile}`
			: undefined,
	});
	writeFileSync(resolve(reportFile), md);
	writeFileSync(resolve(bodyFile), body + "\n");
	console.log(`changed=${changes.length}`);
	const out = process.env["GITHUB_OUTPUT"];
	if (out) {
		writeFileSync(out, `changed=${changes.length}\nhead=${head}\n`, { flag: "a" });
	}
}

function pin(): void {
	ensureUpstream();
	for (const [java, info] of Object.entries(lock.symbols)) {
		const blob = blobOf(java);
		if (blob) {
			info.blob = blob;
			info.loc = locOf(java);
		}
	}
	lock.upstream.commit = git(["rev-parse", "HEAD"]);
	lock.upstream.date = git(["log", "-1", "--format=%cI"]);
	writeFileSync(lockPath, JSON.stringify(lock, null, "\t") + "\n");
	console.log(`pinned to ${lock.upstream.commit}`);
}

const [cmd = "--status", ...args] = process.argv.slice(2);
if (process.argv[1] !== import.meta.filename) {
	// imported (the unit tests): nothing to run
} else
	switch (cmd) {
		case "--fetch":
			fetch();
			break;
		case "--status":
			status();
			break;
		case "--diff":
			diff(args[0]);
			break;
		case "--pin":
			pin();
			break;
		case "--report":
			report(args[0] ?? "upstream-sync.md", args[1] ?? "upstream-sync-body.md");
			break;
		default:
			console.error("unknown option " + cmd);
			process.exit(2);
	}
