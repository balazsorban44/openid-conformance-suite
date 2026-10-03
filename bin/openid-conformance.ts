#!/usr/bin/env node
/**
 * CLI for the OpenID conformance suite port.
 *
 *   openid-conformance list [--plans|--modules|--variants]
 *   openid-conformance run --plan <name> [--variant k=v ...] --config <file> [--module <glob>] [--headed] [-- <playwright args>]
 *   openid-conformance ci --project <name from src/runner/projects.ts> [-- <playwright args>]
 *   openid-conformance projects
 *
 * `run` and `ci` execute Playwright (tests/plan.spec.ts) with the matching CONFORMANCE_* environment.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const require = createRequire(import.meta.url);

function usage(code = 0): never {
	console.log(`openid-conformance - OpenID Connect OP/RP conformance tests (TypeScript port of the OIDF suite)

Usage:
  openid-conformance list [--plans | --modules | --variants]
  openid-conformance run --plan <plan> --config <file> [--variant k=v]... [--module <glob>] [--tls] [--headed] [--report-dir <dir>] [-- <playwright args>]
  openid-conformance ci --project <name> [-- <playwright args>]
  openid-conformance projects

Examples:
  openid-conformance run --plan oidcc-basic-certification-test-plan \\
     --variant server_metadata=discovery --variant client_registration=dynamic_client \\
     --config ./conformance.json
  openid-conformance ci --project op-basic-dynamic
`);
	process.exit(code);
}

function parseArgs(argv: string[]): { cmd: string; opts: Record<string, string | string[] | boolean>; rest: string[] } {
	const [cmd, ...args] = argv;
	const opts: Record<string, string | string[] | boolean> = {};
	const rest: string[] = [];
	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		if (a === "--") {
			rest.push(...args.slice(i + 1));
			break;
		}
		if (a.startsWith("--")) {
			const key = a.slice(2);
			const next = args[i + 1];
			if (next === undefined || next.startsWith("--")) {
				opts[key] = true;
			} else {
				if (key === "variant") {
					opts[key] = [...((opts[key] as string[] | undefined) ?? []), next];
				} else {
					opts[key] = next;
				}
				i++;
			}
		} else {
			rest.push(a);
		}
	}
	return { cmd: cmd ?? "", opts, rest };
}

async function list(opts: Record<string, unknown>): Promise<void> {
	const { modules, plans } = await import("../src/registry.ts");
	const { VariantService } = await import("../src/framework/VariantService.ts");
	const { collectVariantMetadata } = await import("../src/framework/variants.ts");
	const what = opts["modules"] ? "modules" : opts["variants"] ? "variants" : "plans";
	if (what === "plans") {
		for (const p of plans) {
			console.log(`${p.meta.testPlanName}\n    ${p.meta.displayName}`);
			const params = new Set<string>();
			for (const m of VariantService.expandPlan(
				p,
				new (await import("../src/framework/variants.ts")).VariantSelection({}),
			)) {
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
	} else if (what === "modules") {
		for (const m of modules) {
			console.log(`${m.meta?.testName}\n    ${m.meta?.displayName}`);
		}
	} else {
		const seen = new Map<string, Set<string>>();
		for (const m of modules) {
			for (const v of collectVariantMetadata(m).parameters) {
				seen.set(v.parameter.name, new Set(v.values().map(String)));
			}
		}
		for (const [k, vals] of seen) {
			console.log(`${k}: ${[...vals].join(", ")}`);
		}
	}
}

function playwright(env: Record<string, string>, extra: string[]): number {
	const cli = require.resolve("@playwright/test/cli");
	const args = [cli, "test", "tests/plan.spec.ts", "--config", join(root, "playwright.config.ts"), ...extra];
	const r = spawnSync(process.execPath, args, { stdio: "inherit", cwd: root, env: { ...process.env, ...env } });
	return r.status ?? 1;
}

async function main(): Promise<void> {
	const { cmd, opts, rest } = parseArgs(process.argv.slice(2));
	switch (cmd) {
		case "list":
			await list(opts);
			return;
		case "projects": {
			const { projects } = await import("../src/runner/projects.ts");
			for (const p of projects) {
				console.log(`${p.name}\t${p.plan}\t${p.variant}\t${p.config}`);
			}
			return;
		}
		case "run": {
			const plan = opts["plan"];
			const config = opts["config"];
			if (typeof plan !== "string" || typeof config !== "string") {
				usage(1);
			}
			const configPath = resolve(process.cwd(), config);
			if (!existsSync(configPath)) {
				console.error(`config not found: ${configPath}`);
				process.exit(1);
			}
			const variants = (opts["variant"] as string[] | undefined) ?? [];
			const env: Record<string, string> = {
				CONFORMANCE_PLAN: plan,
				CONFORMANCE_CONFIG: configPath,
				CONFORMANCE_VARIANT: variants.map((v) => `[${v}]`).join(""),
			};
			if (typeof opts["module"] === "string") {
				env["CONFORMANCE_MODULE"] = opts["module"];
			}
			if (opts["tls"]) {
				env["CONFORMANCE_TLS"] = "1";
			}
			if (typeof opts["report-dir"] === "string") {
				env["CONFORMANCE_REPORT_DIR"] = resolve(process.cwd(), opts["report-dir"]);
			}
			const extra = [...rest];
			if (opts["headed"]) {
				extra.push("--headed");
			}
			process.exit(playwright(env, extra));
		}
		// eslint-disable-next-line no-fallthrough
		case "ci": {
			const name = opts["project"];
			const { projects } = await import("../src/runner/projects.ts");
			const p = projects.find((x) => x.name === name);
			if (!p) {
				console.error(`unknown project '${String(name)}'; known: ${projects.map((x) => x.name).join(", ")}`);
				process.exit(1);
			}
			process.exit(
				playwright(
					{
						CONFORMANCE_PROJECT: p.name,
						CONFORMANCE_PLAN: p.plan,
						CONFORMANCE_VARIANT: p.variant,
						CONFORMANCE_CONFIG: resolve(root, p.config),
						CONFORMANCE_SUMMARY_TITLE: `OpenID conformance: ${p.name}`,
						CONFORMANCE_TLS: process.env["CONFORMANCE_TLS"] ?? "1",
					},
					rest,
				),
			);
		}
		// eslint-disable-next-line no-fallthrough
		case "help":
		case "--help":
		case "-h":
		case "":
			usage(0);
		// eslint-disable-next-line no-fallthrough
		default:
			console.error(`unknown command '${cmd}'`);
			usage(1);
	}
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
