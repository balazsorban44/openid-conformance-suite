#!/usr/bin/env node
/**
 * Maps upstream Java files to the functions (and tests) that port them in the rewritten suite, and records the
 * mapping in upstream.lock.json under `symbols` (several Java files can map to one TS file, one Java file to one
 * symbol):
 *
 *   "symbols": {
 *     "src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java":
 *       { "blob": "...", "loc": 41, "ts": "src/op/id-token.ts", "symbol": "validateIdTokenNonce" }
 *   }
 *
 * The source of truth is the `upstream:` reference in the doc comment (or line comment) right before an exported
 * function, or before a `test("<module>: ...")` in a spec:
 *
 *   /** upstream: condition/client/ValidateIdTokenNonce.java *\/
 *   export function validateIdTokenNonce(...)
 *
 *   /** ... upstream: sequence/client/PerformStandardIdTokenChecks.java with condition/client/A.java, B.java *\/
 *
 * (a bare `B.java` is in the directory of the reference before it). The blob is taken from the `files` entry of the
 * same Java file when it is pinned there (same upstream commit), else hashed from the upstream checkout
 * ($UPSTREAM or .upstream/, at the pinned commit).
 *
 *   node scripts/upstream-lock-symbols.ts           # report what would change
 *   node scripts/upstream-lock-symbols.ts --write   # update upstream.lock.json
 *   node scripts/upstream-lock-symbols.ts --check   # exit 1 when the lock is not up to date (CI)
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const lockPath = join(root, "upstream.lock.json");
const upstreamDir = process.env["UPSTREAM"] ?? join(root, ".upstream");
const JAVA_ROOT = "src/main/java/net/openid/conformance/";
/** Where rewritten code lives (the old 1:1 ports under src/condition etc. are tracked in `files`) */
const SCAN = ["src/suite", "src/op", "src/rp", "tests"];

export interface SymbolEntry {
	blob: string;
	loc: number;
	ts: string;
	symbol: string;
}

interface LockFile {
	upstream: { repo: string; commit: string; date: string };
	files: Record<string, { java: string; blob: string; loc: number }>;
	symbols?: Record<string, SymbolEntry>;
}

/** The Java files named after "upstream:" in a comment ("A.java, B.java" share A's directory) */
export function javaReferences(comment: string): string[] {
	const at = comment.indexOf("upstream:");
	if (at === -1) {
		return [];
	}
	const out: string[] = [];
	let dir = "";
	for (const m of comment.substring(at).matchAll(/([\w/]*?)(\w+)\.java\b/g)) {
		if (m[1]) {
			dir = m[1];
		}
		out.push(dir + m[2] + ".java");
	}
	return out;
}

/**
 * [java path relative to the conformance package, symbol, primary] for every reference in a TS source; `primary`
 * when the function ports that file (the only file its comment names, or the first one followed by "with ..."),
 * rather than listing it among the conditions a group calls
 */
export function referencesIn(source: string): [string, string, boolean][] {
	const out: [string, string, boolean][] = [];
	// a comment block (one /** ... */ or // lines) directly followed by a function (exported or a module-private
	// helper that several exported checks share) or a test
	const re =
		/((?:\/\*\*(?:[^*]|\*(?!\/))*\*\/|(?:[ \t]*\/\/[^\n]*\n)+))\s*(?:(?:export\s+)?(?:async\s+)?function\s+(\w+)|test(?:\.\w+)?\(\s*["'`]([\w.-]+):)/g;
	for (const m of source.matchAll(re)) {
		const symbol = m[2] ?? m[3];
		const refs = javaReferences(m[1]);
		// the function ports the first file it names when that is the only one, or when the others follow "with"
		const ownsFirst = refs.length === 1 || / with /.test(m[1].substring(m[1].indexOf(refs[0])));
		refs.forEach((java, i) => out.push([java, symbol, i === 0 && ownsFirst]));
	}
	return out;
}

function walk(dir: string): string[] {
	if (!existsSync(dir)) {
		return [];
	}
	return readdirSync(dir, { recursive: true, encoding: "utf8" })
		.filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
		.map((f) => join(dir, f));
}

function blobOf(javaPath: string, lock: LockFile): { blob: string; loc: number } | null {
	const pinned = Object.values(lock.files).find((f) => f.java === javaPath);
	if (pinned) {
		return { blob: pinned.blob, loc: pinned.loc };
	}
	if (!existsSync(join(upstreamDir, ".git"))) {
		return null;
	}
	try {
		const spec = `${lock.upstream.commit}:${javaPath}`;
		const blob = execFileSync("git", ["rev-parse", spec], { cwd: upstreamDir, encoding: "utf8" }).trim();
		const loc = execFileSync("git", ["cat-file", "-p", spec], { cwd: upstreamDir, encoding: "utf8" }).split(
			"\n",
		).length;
		return { blob, loc };
	} catch {
		return null;
	}
}

function main(argv: string[]): number {
	const lock = JSON.parse(readFileSync(lockPath, "utf8")) as LockFile;
	const wanted: Record<string, SymbolEntry> = {};
	const primary = new Set<string>();
	const problems: string[] = [];
	for (const file of SCAN.flatMap((d) => walk(join(root, d)))) {
		const ts = relative(root, file);
		for (const [java, symbol, isPrimary] of referencesIn(readFileSync(file, "utf8"))) {
			const javaPath = JAVA_ROOT + java;
			// one Java file, one place: the function whose comment names it first, else the first that names it
			if (primary.has(javaPath) || (wanted[javaPath] && !isPrimary)) {
				continue;
			}
			const pin = blobOf(javaPath, lock);
			if (!pin) {
				problems.push(`${ts}#${symbol}: ${javaPath} is neither pinned in "files" nor in the upstream checkout`);
				continue;
			}
			wanted[javaPath] = { ...pin, ts, symbol };
			if (isPrimary) {
				primary.add(javaPath);
			}
		}
	}
	const current = lock.symbols ?? {};
	const sorted = Object.fromEntries(Object.entries(wanted).sort(([a], [b]) => a.localeCompare(b)));
	const changes = [
		...Object.keys(sorted)
			.filter((k) => JSON.stringify(sorted[k]) !== JSON.stringify(current[k]))
			.map((k) => `${current[k] ? "~" : "+"} ${k} -> ${sorted[k].ts}#${sorted[k].symbol}`),
		...Object.keys(current)
			.filter((k) => !sorted[k])
			.map((k) => `- ${k}`),
	];
	for (const line of [...problems, ...changes]) {
		console.log(line);
	}
	if (argv.includes("--write")) {
		lock.symbols = sorted;
		writeFileSync(lockPath, JSON.stringify(lock, null, "\t") + "\n");
		console.log(`${Object.keys(sorted).length} symbol entries written to upstream.lock.json`);
		return problems.length > 0 ? 1 : 0;
	}
	if (changes.length === 0 && problems.length === 0) {
		console.log(`upstream.lock.json symbols are up to date (${Object.keys(sorted).length} entries)`);
		return 0;
	}
	return argv.includes("--check") ? 1 : 0;
}

if (import.meta.main) {
	process.exitCode = main(process.argv.slice(2));
}
