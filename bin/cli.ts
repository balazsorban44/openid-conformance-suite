#!/usr/bin/env node
/**
 * openid-conformance: run the OpenID Connect OP/RP conformance tests (TypeScript port of the OIDF suite).
 *
 *   openid-conformance list [--plans|--modules|--variants]
 *   openid-conformance run --plan <name> --config <file> [--variant k=v]... [--module <glob>] [--tls] [--headed] [--report-dir <dir>] [-- <playwright args>]
 *   openid-conformance ci --project <name> [-- <playwright args>]
 *   openid-conformance projects [--json]
 *
 * `run` and `ci` execute Playwright with the matching CONFORMANCE_* environment; playwright.config.ts picks the spec
 * files (tests/op/*.spec.ts for ported modules, tests/plan.spec.ts for the rest).
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, Option } from "commander";
import { projects } from "../src/runner/projects.ts";

const root = resolve(import.meta.dirname, "..");

function playwright(env: Record<string, string>, extra: string[]): number {
	const cli = fileURLToPath(import.meta.resolve("@playwright/test/cli"));
	const r = spawnSync(process.execPath, [cli, "test", "--config", join(root, "playwright.config.ts"), ...extra], {
		stdio: "inherit",
		cwd: root,
		// CONFORMANCE_CWD: the directory `target.command` of the config runs in (the caller's working directory)
		env: { CONFORMANCE_CWD: process.cwd(), ...process.env, ...env },
	});
	return r.status ?? 1;
}

interface RunOptions {
	plan: string;
	config: string;
	variant?: string[];
	module?: string;
	tls?: boolean;
	headed?: boolean;
	reportDir?: string;
}

const program = new Command("openid-conformance")
	.description("OpenID Connect OP/RP conformance tests (TypeScript port of the OpenID Foundation suite)")
	.showHelpAfterError()
	.addHelpText(
		"after",
		`
Examples:
  openid-conformance run --plan oidcc-basic-certification-test-plan \\
     --variant server_metadata=discovery --variant client_registration=dynamic_client \\
     --config ./conformance.json
  openid-conformance ci --project op-basic-dynamic`,
	);

program
	.command("list")
	.description("list the test plans (default), modules or variant parameters")
	.option("--plans", "the test plans and their user-selectable variants")
	.option("--modules", "the test modules")
	.option("--variants", "the variant parameters and their values")
	.action(async (opts: { modules?: boolean; variants?: boolean }) => {
		const { listRegistry } = await import("../src/runner/list.ts");
		const what = opts.modules ? "modules" : opts.variants ? "variants" : "plans";
		console.log(listRegistry(what).join("\n"));
	});

program
	.command("run")
	.description("run a test plan against your implementation")
	.requiredOption("--plan <plan>", "test plan name (see `list`)")
	.requiredOption("--config <file>", "test configuration (.json or .ts)")
	.addOption(
		new Option("--variant <k=v>", "variant selection, repeatable").argParser((v: string, prev: string[] = []) => [
			...prev,
			v,
		]),
	)
	.option("--module <glob>", "only run test modules whose name matches this glob")
	.option("--tls", "serve the suite over https (bundled localhost certificate)")
	.option("--headed", "show the scripted browser")
	.option("--report-dir <dir>", "where results.json and summary.md are written")
	.argument("[playwright...]", "extra Playwright arguments (after --)")
	.action((extra: string[], opts: RunOptions) => {
		const configPath = resolve(process.cwd(), opts.config);
		if (!existsSync(configPath)) {
			program.error(`config not found: ${configPath}`);
		}
		const env: Record<string, string> = { CONFORMANCE_PLAN: opts.plan, CONFORMANCE_CONFIG: configPath };
		if (opts.variant) {
			env["CONFORMANCE_VARIANT"] = opts.variant.map((v) => `[${v}]`).join("");
		}
		if (opts.module) {
			env["CONFORMANCE_MODULE"] = opts.module;
		}
		if (opts.tls) {
			env["CONFORMANCE_TLS"] = "1";
		}
		if (opts.reportDir) {
			env["CONFORMANCE_REPORT_DIR"] = resolve(process.cwd(), opts.reportDir);
		}
		process.exitCode = playwright(env, opts.headed ? [...extra, "--headed"] : extra);
	});

program
	.command("ci")
	.description("run one CI project (see `projects`) against its bundled target")
	.requiredOption("--project <name>", "project name")
	.argument("[playwright...]", "extra Playwright arguments (after --)")
	.action((extra: string[], opts: { project: string }) => {
		const p = projects.find((x) => x.name === opts.project);
		if (!p) {
			return program.error(`unknown project '${opts.project}'; known: ${projects.map((x) => x.name).join(", ")}`);
		}
		process.exitCode = playwright(
			{
				CONFORMANCE_PROJECT: p.name,
				CONFORMANCE_PLAN: p.plan,
				CONFORMANCE_VARIANT: p.variant,
				CONFORMANCE_CONFIG: resolve(root, p.config),
				CONFORMANCE_SUMMARY_TITLE: `OpenID conformance: ${p.name}`,
				CONFORMANCE_TLS: process.env["CONFORMANCE_TLS"] ?? "1",
			},
			extra,
		);
	});

program
	.command("projects")
	.description("list the CI projects (the GitHub Actions matrix)")
	.option("--json", "names only, as a JSON array")
	.action((opts: { json?: boolean }) => {
		if (opts.json) {
			console.log(JSON.stringify(projects.map((p) => p.name)));
			return;
		}
		for (const p of projects) {
			console.log(`${p.name}\t${p.plan}\t${p.variant}\t${p.config}`);
		}
	});

await program.parseAsync();
