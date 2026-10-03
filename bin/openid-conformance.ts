#!/usr/bin/env node
/**
 * CLI for the OpenID conformance suite port.
 *
 *   openid-conformance list [--plans|--modules|--variants]
 *   openid-conformance run --plan <name> [--variant k=v ...] --config <file> [--module <glob>] [--headed] [-- <playwright args>]
 *   openid-conformance ci --project <name from src/runner/projects.ts> [-- <playwright args>]
 *   openid-conformance projects [--json]
 *
 * `run` and `ci` execute Playwright (tests/plan.spec.ts) with the matching CONFORMANCE_* environment.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(import.meta.dirname, "..");

type Opts = Record<string, string | string[] | true>;

function usage(code: number): number {
	console.log(`openid-conformance - OpenID Connect OP/RP conformance tests (TypeScript port of the OIDF suite)

Usage:
  openid-conformance list [--plans | --modules | --variants]
  openid-conformance run --plan <plan> --config <file> [--variant k=v]... [--module <glob>] [--tls] [--headed] [--report-dir <dir>] [-- <playwright args>]
  openid-conformance ci --project <name> [-- <playwright args>]
  openid-conformance projects [--json]

Examples:
  openid-conformance run --plan oidcc-basic-certification-test-plan \\
     --variant server_metadata=discovery --variant client_registration=dynamic_client \\
     --config ./conformance.json
  openid-conformance ci --project op-basic-dynamic
`);
	return code;
}

/** `--key value`, `--flag` (when followed by nothing or another `--option`), repeatable `--variant`, `-- rest` */
function parseArgs(argv: string[]): { cmd: string; opts: Opts; rest: string[] } {
	const [cmd = "", ...args] = argv;
	const opts: Opts = {};
	const rest: string[] = [];
	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		if (a === "--") {
			rest.push(...args.slice(i + 1));
			break;
		}
		if (!a.startsWith("--")) {
			rest.push(a);
			continue;
		}
		const key = a.slice(2);
		const next = args[i + 1];
		if (next === undefined || next.startsWith("--")) {
			opts[key] = true;
			continue;
		}
		i++;
		const prev = opts[key];
		opts[key] = key === "variant" ? [...(Array.isArray(prev) ? prev : []), next] : next;
	}
	return { cmd, opts, rest };
}

async function list(opts: Opts): Promise<void> {
	const { modules, plans } = await import("../src/registry.ts");
	const { expandPlan } = await import("../src/framework/VariantService.ts");
	const { collectVariantMetadata, VariantSelection } = await import("../src/framework/variants.ts");
	if (opts["modules"]) {
		for (const m of modules) {
			console.log(`${m.meta?.testName}\n    ${m.meta?.displayName}`);
		}
	} else if (opts["variants"]) {
		const seen = new Map<string, Set<string>>();
		for (const m of modules) {
			for (const v of collectVariantMetadata(m).parameters) {
				seen.set(v.parameter.name, new Set(v.values().map(String)));
			}
		}
		for (const [k, vals] of seen) {
			console.log(`${k}: ${[...vals].join(", ")}`);
		}
	} else {
		for (const p of plans) {
			console.log(`${p.meta.testPlanName}\n    ${p.meta.displayName}`);
			const params = new Set<string>();
			for (const m of expandPlan(p, new VariantSelection({}))) {
				for (const v of collectVariantMetadata(m.moduleClass).parameters) {
					if (!m.variantFromPlanDefinition.has(v)) {
						params.add(`${v.parameter.name}=${v.values().map(String).join("|")}`);
					}
				}
			}
			if (params.size > 0) {
				console.log(`    variants: ${[...params].join(" ")}`);
			}
		}
	}
}

function playwright(env: Record<string, string>, extra: string[]): number {
	const cli = fileURLToPath(import.meta.resolve("@playwright/test/cli"));
	const args = [cli, "test", "tests/plan.spec.ts", "--config", join(root, "playwright.config.ts"), ...extra];
	const r = spawnSync(process.execPath, args, {
		stdio: "inherit",
		cwd: root,
		// CONFORMANCE_CWD: the directory `target.command` of the config runs in (the caller's working directory)
		env: { CONFORMANCE_CWD: process.cwd(), ...process.env, ...env },
	});
	return r.status ?? 1;
}

function run(opts: Opts, rest: string[]): number {
	const { plan, config, variant, module, tls, headed } = opts;
	const reportDir = opts["report-dir"];
	if (typeof plan !== "string" || typeof config !== "string") {
		return usage(1);
	}
	const configPath = resolve(process.cwd(), config);
	if (!existsSync(configPath)) {
		console.error(`config not found: ${configPath}`);
		return 1;
	}
	const env: Record<string, string> = { CONFORMANCE_PLAN: plan, CONFORMANCE_CONFIG: configPath };
	if (Array.isArray(variant)) {
		env["CONFORMANCE_VARIANT"] = variant.map((v) => `[${v}]`).join("");
	}
	if (typeof module === "string") {
		env["CONFORMANCE_MODULE"] = module;
	}
	if (tls) {
		env["CONFORMANCE_TLS"] = "1";
	}
	if (typeof reportDir === "string") {
		env["CONFORMANCE_REPORT_DIR"] = resolve(process.cwd(), reportDir);
	}
	return playwright(env, headed ? [...rest, "--headed"] : rest);
}

async function main(): Promise<number> {
	const { cmd, opts, rest } = parseArgs(process.argv.slice(2));
	switch (cmd) {
		case "list":
			await list(opts);
			return 0;
		case "projects": {
			const { projects } = await import("../src/runner/projects.ts");
			if (opts["json"]) {
				console.log(JSON.stringify(projects.map((p) => p.name)));
			} else {
				for (const p of projects) {
					console.log(`${p.name}\t${p.plan}\t${p.variant}\t${p.config}`);
				}
			}
			return 0;
		}
		case "run":
			return run(opts, rest);
		case "ci": {
			const { projects } = await import("../src/runner/projects.ts");
			const p = projects.find((x) => x.name === opts["project"]);
			if (!p) {
				console.error(`unknown project '${String(opts["project"])}'; known: ${projects.map((x) => x.name).join(", ")}`);
				return 1;
			}
			return playwright(
				{
					CONFORMANCE_PROJECT: p.name,
					CONFORMANCE_PLAN: p.plan,
					CONFORMANCE_VARIANT: p.variant,
					CONFORMANCE_CONFIG: resolve(root, p.config),
					CONFORMANCE_SUMMARY_TITLE: `OpenID conformance: ${p.name}`,
					CONFORMANCE_TLS: process.env["CONFORMANCE_TLS"] ?? "1",
				},
				rest,
			);
		}
		case "help":
		case "--help":
		case "-h":
		case "":
			return usage(0);
		default:
			console.error(`unknown command '${cmd}'`);
			return usage(1);
	}
}

process.exitCode = await main().catch((e: unknown) => {
	console.error(e);
	return 1;
});
