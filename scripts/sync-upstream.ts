#!/usr/bin/env node
/**
 * Compare the ported files with the upstream Java suite. See .claude/skills/sync-upstream/SKILL.md.
 *
 *   node scripts/sync-upstream.ts --fetch                 clone/update upstream into .upstream/
 *   node scripts/sync-upstream.ts [--status]              list ported files whose Java source changed since the pin
 *   node scripts/sync-upstream.ts --diff <ts path>        git diff of the Java source (pinned..HEAD)
 *   node scripts/sync-upstream.ts --closure <JavaFQN>...  Java files in the plans' closure missing from the lock
 *   node scripts/sync-upstream.ts --add <JavaFQN>...      add those files (and their closure) to the lock
 *   node scripts/sync-upstream.ts --pin                   re-pin commit + blob hashes to upstream HEAD
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const lockPath = join(root, "upstream.lock.json");
const upstreamDir = process.env["UPSTREAM"] ?? join(root, ".upstream");

interface LockFile {
	upstream: { repo: string; commit: string; date: string };
	files: Record<string, { java: string; blob: string; loc: number; note?: string }>;
}

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

function blobOf(javaPath: string): string | null {
	const p = join(upstreamDir, javaPath);
	if (!existsSync(p)) {
		return null;
	}
	return git(["hash-object", p]);
}

function status(): void {
	ensureUpstream();
	const changed: string[] = [];
	const deleted: string[] = [];
	let unchanged = 0;
	for (const [ts, info] of Object.entries(lock.files)) {
		const blob = blobOf(info.java);
		if (blob === null) {
			deleted.push(ts);
		} else if (blob !== info.blob) {
			changed.push(ts);
		} else {
			unchanged++;
		}
	}
	console.log(`upstream HEAD ${git(["rev-parse", "HEAD"])}, pinned ${lock.upstream.commit}`);
	console.log(`unchanged: ${unchanged}`);
	console.log(`changed: ${changed.length}`);
	for (const c of changed) {
		console.log(`  ${c}  <- ${lock.files[c].java}`);
	}
	console.log(`deleted upstream: ${deleted.length}`);
	for (const d of deleted) {
		console.log(`  ${d}  <- ${lock.files[d].java}`);
	}
	process.exitCode = changed.length + deleted.length > 0 ? 1 : 0;
}

function diff(ts: string): void {
	ensureUpstream();
	const info = lock.files[ts];
	if (!info) {
		console.error(`not in lock: ${ts}`);
		process.exit(2);
	}
	const out = execFileSync("git", ["diff", lock.upstream.commit, "HEAD", "--", info.java], { cwd: upstreamDir, encoding: "utf8" });
	process.stdout.write(out || "(no changes)\n");
}

const JAVA_ROOT = "src/main/java/";

function javaPathOf(fqn: string): string {
	return JAVA_ROOT + fqn.replaceAll(".", "/") + ".java";
}

function tsPathOf(fqn: string): string {
	const rel = fqn.replace("net.openid.conformance.", "");
	const parts = rel.split(".");
	if (["testmodule", "frontchannel", "plan"].includes(parts[0])) {
		return `src/framework/${parts.at(-1)}.ts`;
	}
	return "src/" + parts.join("/") + ".ts";
}

const SKIP_PACKAGES = [
	"net.openid.conformance.apidoc",
	"net.openid.conformance.info",
	"net.openid.conformance.logging",
	"net.openid.conformance.security",
	"net.openid.conformance.sharing",
	"net.openid.conformance.statistics",
	"net.openid.conformance.pagination",
	"net.openid.conformance.runner",
	"net.openid.conformance.settings",
	"net.openid.conformance.extensions",
	"net.openid.conformance.support",
	"net.openid.conformance.token",
	"net.openid.conformance.ui",
	"net.openid.conformance.export",
	"net.openid.conformance.CollapsingGson",
	"net.openid.conformance.SwaggerConfig",
	"net.openid.conformance.variant",
];

/** Transitive closure of upstream Java classes referenced by the given classes (imports + same-package names). */
function closure(starts: string[]): string[] {
	ensureUpstream();
	const index = new Map<string, string>();
	const all = git(["ls-files", "src/main/java"]).split("\n");
	for (const p of all) {
		if (p.endsWith(".java")) {
			index.set(p.slice(JAVA_ROOT.length, -5).replaceAll("/", "."), p);
		}
	}
	const seen = new Set<string>();
	const stack = [...starts];
	while (stack.length > 0) {
		const x = stack.pop() as string;
		if (seen.has(x) || !index.has(x) || SKIP_PACKAGES.some((s) => x.startsWith(s))) {
			continue;
		}
		seen.add(x);
		const src = readFileSync(join(upstreamDir, index.get(x) as string), "utf8");
		for (const m of src.matchAll(/^import (net\.openid\.conformance\.[\w.]+);/gm)) {
			stack.push(m[1]);
		}
		const pkg = x.slice(0, x.lastIndexOf("."));
		for (const m of src.matchAll(/\b([A-Z][A-Za-z0-9_]+)\b/g)) {
			const cand = pkg + "." + m[1];
			if (index.has(cand) && cand !== x) {
				stack.push(cand);
			}
		}
	}
	return [...seen].sort();
}

function missingFromLock(fqns: string[]): string[] {
	const known = new Set(Object.values(lock.files).map((f) => f.java));
	return closure(fqns).filter((fqn) => !known.has(javaPathOf(fqn)));
}

function add(fqns: string[]): void {
	for (const fqn of missingFromLock(fqns)) {
		const java = javaPathOf(fqn);
		const ts = tsPathOf(fqn);
		const blob = blobOf(java);
		if (!blob) {
			continue;
		}
		const loc = readFileSync(join(upstreamDir, java), "utf8").split("\n").length;
		lock.files[ts] = { java, blob, loc };
		console.log(`added ${ts} <- ${java}`);
	}
	save();
}

function pin(): void {
	ensureUpstream();
	for (const info of Object.values(lock.files)) {
		const blob = blobOf(info.java);
		if (blob) {
			info.blob = blob;
			info.loc = readFileSync(join(upstreamDir, info.java), "utf8").split("\n").length;
		}
	}
	lock.upstream.commit = git(["rev-parse", "HEAD"]);
	lock.upstream.date = git(["log", "-1", "--format=%cI"]);
	save();
	console.log(`pinned to ${lock.upstream.commit}`);
}

function save(): void {
	lock.files = Object.fromEntries(Object.entries(lock.files).sort(([a], [b]) => a.localeCompare(b)));
	writeFileSync(lockPath, JSON.stringify(lock, null, 2) + "\n");
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
	case "--closure":
		for (const f of missingFromLock(args)) {
			console.log(`${f}  (${javaPathOf(f)} -> ${tsPathOf(f)})`);
		}
		break;
	case "--add":
		add(args);
		break;
	case "--pin":
		pin();
		break;
	default:
		console.error("unknown option " + cmd);
		process.exit(2);
}
