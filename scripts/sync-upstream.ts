#!/usr/bin/env node
/**
 * Compare the ported functions and tests with the upstream Java suite. See .claude/skills/sync-upstream/SKILL.md.
 *
 *   node scripts/sync-upstream.ts --fetch                 clone/update upstream into .upstream/ ($UPSTREAM)
 *   node scripts/sync-upstream.ts [--status]              list ported symbols whose Java source changed since the pin
 *   node scripts/sync-upstream.ts --diff <ts>#<symbol>    git diff of the Java files a function/test ports (pinned..HEAD)
 *   node scripts/sync-upstream.ts --diff <ts path>        the same for every symbol of a TS file
 *   node scripts/sync-upstream.ts --pin                   re-pin commit + blob hashes to upstream HEAD
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
	default:
		console.error("unknown option " + cmd);
		process.exit(2);
}
