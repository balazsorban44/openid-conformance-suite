/** The suite's plans, CI projects and test configurations (src/runner/projects.ts, configs/) */
import { readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { plans, projects } from "../../src/runner/projects.ts";
import { suiteRoot } from "./paths.ts";
import type { ConformanceProject, PlanInfo } from "./types.ts";

export { plans, projects };

export function planKind(plan: string): "OP" | "RP" {
	return plans[plan]?.spec.startsWith("tests/rp/") ? "RP" : "OP";
}

export function planInfos(): PlanInfo[] {
	return Object.entries(plans).map(([name, p]) => ({
		...p,
		name,
		kind: planKind(name),
		projects: projects.filter((x) => x.plan === name).map((x) => x.name),
	}));
}

export function findProject(name: string): ConformanceProject | undefined {
	return projects.find((p) => p.name === name);
}

/** The test configurations under configs/ (not the expected-failures/skips lists or certificates), relative paths */
export async function listConfigs(): Promise<string[]> {
	const base = join(suiteRoot, "configs");
	const out: string[] = [];
	let files: string[];
	try {
		files = await readdir(base, { recursive: true });
	} catch {
		return out;
	}
	for (const f of files) {
		if (/^(expected-failures|expected-skips|certs)\//.test(f) || !/\.(json|ts)$/.test(f)) {
			continue;
		}
		out.push(relative(suiteRoot, join(base, f)));
	}
	return out.sort();
}
