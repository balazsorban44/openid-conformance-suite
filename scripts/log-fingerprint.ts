#!/usr/bin/env node
/**
 * Log fidelity check: fingerprints the per-module event logs (test-results/<test>/log.json) so a framework
 * refactor can prove it did not change any log entry the ported tests produce.
 *
 *   node scripts/log-fingerprint.ts --out baseline.json test-results [more dirs...]
 *   node scripts/log-fingerprint.ts --diff baseline.json current.json [--allow allowed.json] [--strict-order]
 *
 * Fingerprint of an entry: [src, result ?? null, requirements ?? null, normalise(msg), marker] where marker is
 * "http:<request|response|incoming|outgoing>", "startBlock" or null. normalise() masks values that differ between
 * runs (test ids, localhost ports, random strings, timestamps, UUIDs, epoch numbers). Modules are keyed by
 * "<testName><variantString>" from the module-report.json next to the log (the plan is appended on collisions).
 *
 * --diff prints the added (+), removed (-) and changed (~, same src/result/requirements/marker, other message)
 * entries per module and exits 1 when anything differs. --allow takes a JSON array of regexes; a changed entry
 * whose old or new message matches one of them is not reported. Entries that only moved (>) are listed but do not
 * fail the diff, because concurrent flows (scripted browser vs. test module) interleave differently from run to
 * run; pass --strict-order to fail on them as well.
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export type Fingerprint = [string, string | null, string[] | null, string | null, string | null];
export type Fingerprints = Record<string, Fingerprint[]>;

/** True when a >= 10 character token looks generated rather than like a word or identifier */
function looksRandom(token: string): boolean {
	if (Math.max(...token.split(/[-_]/).map((s) => s.length)) < 6) {
		return false; // e.g. "0000-MM-DD", "client_secret_basic"
	}
	if (/\d/.test(token) && /[A-Za-z]/.test(token)) {
		return true;
	}
	const letters = token.replace(/[^A-Za-z]/g, "");
	let changes = 0;
	for (let i = 1; i < letters.length; i++) {
		if (/[A-Z]/.test(letters[i]) !== /[A-Z]/.test(letters[i - 1])) {
			changes++;
		}
	}
	// camelCase identifiers change case about once per word; random strings about every other character
	return letters.length > 1 && changes / (letters.length - 1) >= 0.4;
}

export function normalise(msg: string): string {
	return msg
		.replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g, "<time>")
		.replace(/\b(https?:\/\/)(localhost|127\.0\.0\.1|\[::1\]):\d+/g, "$1$2:<port>")
		.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<uuid>")
		.replace(/\b[0-9a-f]{12}(?:-\d+)?\b/g, (m) => (m.includes("-") ? "<id>-<n>" : "<id>"))
		.replace(/[A-Za-z0-9_-]{10,}/g, (m) => (/^\d+$/.test(m) ? m : looksRandom(m) ? "<random>" : m))
		.replace(/\b\d{10}(?:\d{3})?\b/g, "<epoch>")
		.replace(/\b(sid|session|session_state|session_id)([=:]\s*)\S+/gi, "$1$2<session>");
}

function fingerprintEntry(e: Record<string, unknown>): Fingerprint {
	const reqs = Array.isArray(e["requirements"]) ? (e["requirements"] as string[]) : null;
	const marker = e["http"] != null ? "http:" + String(e["http"]) : e["startBlock"] === true ? "startBlock" : null;
	return [
		String(e["src"]),
		e["result"] == null ? null : String(e["result"]),
		reqs,
		typeof e["msg"] === "string" ? normalise(e["msg"]) : null,
		marker,
	];
}

export function fingerprintDirs(dirs: string[]): Fingerprints {
	const result: Fingerprints = {};
	const logs = dirs.flatMap((d) =>
		readdirSync(d, { recursive: true, encoding: "utf8" })
			.filter((f) => basename(f) === "log.json")
			.sort()
			.map((f) => join(d, f)),
	);
	for (const file of logs) {
		const reportFile = join(dirname(file), "module-report.json");
		const report = existsSync(reportFile) ? JSON.parse(readFileSync(reportFile, "utf8")) : null;
		let key = report ? `${report.testName}${report.variantString ?? ""}` : dirname(file);
		if (key in result && report?.plan) {
			key += ` (${report.plan})`;
		}
		for (let n = 2; key in result; n++) {
			key = key.replace(/ #\d+$/, "") + ` #${n}`;
		}
		const entries = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>[];
		result[key] = entries.map(fingerprintEntry);
	}
	return Object.fromEntries(Object.entries(result).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

type Op = { kind: "+" | "-" | "~" | ">"; old?: Fingerprint; cur?: Fingerprint };

/**
 * LCS diff of two fingerprint lists. An entry removed in one place and added unchanged in another moved (>); a
 * removed and an added entry of the same shape in one hunk are a change (~).
 */
export function diffModule(a: Fingerprint[], b: Fingerprint[], allow: RegExp[]): Op[] {
	const sa = a.map((x) => JSON.stringify(x));
	const sb = b.map((x) => JSON.stringify(x));
	const w = b.length + 1;
	const lcs = new Uint32Array((a.length + 1) * w);
	for (let i = a.length - 1; i >= 0; i--) {
		for (let j = b.length - 1; j >= 0; j--) {
			lcs[i * w + j] =
				sa[i] === sb[j] ? lcs[(i + 1) * w + j + 1] + 1 : Math.max(lcs[(i + 1) * w + j], lcs[i * w + j + 1]);
		}
	}
	const hunks: { removed: Fingerprint[]; added: Fingerprint[] }[] = [];
	const common = (i: number, j: number) => i < a.length && j < b.length && sa[i] === sb[j];
	let i = 0;
	let j = 0;
	while (i < a.length || j < b.length) {
		if (common(i, j)) {
			i++;
			j++;
			continue;
		}
		const hunk = { removed: [] as Fingerprint[], added: [] as Fingerprint[] }; // up to the next common entry
		while ((i < a.length || j < b.length) && !common(i, j)) {
			if (i < a.length && (j === b.length || lcs[(i + 1) * w + j] >= lcs[i * w + j + 1])) {
				hunk.removed.push(a[i++]);
			} else {
				hunk.added.push(b[j++]);
			}
		}
		hunks.push(hunk);
	}
	const ops: Op[] = [];
	const key = (x: Fingerprint) => JSON.stringify(x);
	for (const h of hunks) {
		h.removed = h.removed.filter((old) => {
			const moved = hunks.find((o) => o.added.some((cur) => key(cur) === key(old)));
			if (moved) {
				moved.added.splice(
					moved.added.findIndex((cur) => key(cur) === key(old)),
					1,
				);
				ops.push({ kind: ">", old });
			}
			return !moved;
		});
	}
	const shape = (x: Fingerprint) => JSON.stringify([x[0], x[1], x[2], x[4]]);
	for (const { removed, added } of hunks) {
		for (const old of removed) {
			const k = added.findIndex((cur) => shape(cur) === shape(old));
			if (k === -1) {
				ops.push({ kind: "-", old });
				continue;
			}
			const [cur] = added.splice(k, 1);
			if (!allow.some((re) => re.test(old[3] ?? "") || re.test(cur[3] ?? ""))) {
				ops.push({ kind: "~", old, cur });
			}
		}
		ops.push(...added.map((cur): Op => ({ kind: "+", cur })));
	}
	return ops;
}

function show(f: Fingerprint): string {
	const [src, result, reqs, msg, marker] = f;
	return `${src}${result ? ` [${result}]` : ""}${reqs ? ` {${reqs.join(", ")}}` : ""}${marker ? ` <${marker}>` : ""}: ${msg ?? "(no msg)"}`;
}

export function diff(
	baseline: Fingerprints,
	current: Fingerprints,
	allow: RegExp[],
	strictOrder = false,
): { lines: string[]; failed: boolean } {
	const lines: string[] = [];
	let failed = false;
	for (const key of [...new Set([...Object.keys(baseline), ...Object.keys(current)])].sort()) {
		if (!(key in current) || !(key in baseline)) {
			lines.push(`!!! module only in ${key in current ? "current" : "baseline"}: ${key}`);
			failed = true;
			continue;
		}
		const ops = diffModule(baseline[key], current[key], allow);
		if (ops.length > 0) {
			lines.push(`=== ${key}`);
			for (const op of ops) {
				failed ||= op.kind !== ">" || strictOrder;
				if (op.kind === "~") {
					lines.push(`  ~ ${show(op.old as Fingerprint)}`, `    -> ${op.cur?.[3] ?? "(no msg)"}`);
				} else {
					lines.push(`  ${op.kind} ${show((op.old ?? op.cur) as Fingerprint)}`);
				}
			}
		}
	}
	return { lines, failed };
}

function main(argv: string[]): number {
	const opt = (name: string) => {
		const i = argv.indexOf(name);
		return i === -1 ? null : argv.splice(i, 2)[1];
	};
	const out = opt("--out");
	const allowFile = opt("--allow");
	const strictOrder = argv.includes("--strict-order");
	const diffIdx = argv.indexOf("--diff");
	if (diffIdx !== -1) {
		const [baseFile, curFile] = argv.slice(diffIdx + 1, diffIdx + 3);
		const read = (f: string) => JSON.parse(readFileSync(f, "utf8")) as Fingerprints;
		const allow = allowFile ? (read(allowFile) as unknown as string[]).map((s) => new RegExp(s)) : [];
		const { lines, failed } = diff(read(baseFile), read(curFile), allow, strictOrder);
		console.log(lines.length === 0 ? "Log fingerprints match." : lines.join("\n"));
		if (lines.length > 0 && !failed) {
			console.log("Only moved entries (>): treated as a match, use --strict-order to fail on them.");
		}
		return failed ? 1 : 0;
	}
	if (!out || argv.length === 0) {
		console.error(
			"usage: log-fingerprint.ts --out <file> <dir>... | --diff <base> <current> [--allow <file>] [--strict-order]",
		);
		return 2;
	}
	const fp = fingerprintDirs(argv);
	// one entry per line keeps the file reviewable with a plain text diff
	const body = Object.entries(fp).map(
		([k, list]) => `${JSON.stringify(k)}: [\n${list.map((f) => "  " + JSON.stringify(f)).join(",\n")}\n ]`,
	);
	writeFileSync(out, `{\n ${body.join(",\n ")}\n}\n`);
	console.log(`Wrote ${Object.keys(fp).length} module fingerprints to ${out}`);
	return 0;
}

if (import.meta.main) {
	process.exitCode = main(process.argv.slice(2));
}
