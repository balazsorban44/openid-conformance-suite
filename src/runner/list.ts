import { plans, projects } from "./projects.ts";

/** "[k=v][k2=v2]" -> [[k, v], [k2, v2]] */
function variantEntries(s: string): [string, string][] {
	return [...s.matchAll(/\[([^=\]]+)=([^\]]*)\]/g)].map((m) => [m[1], m[2]]);
}

function add(values: Map<string, Set<string>>, parameter: string, value: string): void {
	values.set(parameter, (values.get(parameter) ?? new Set()).add(value));
}

/**
 * `openid-conformance list`: the test plans (`plans` in src/runner/projects.ts) with their spec file, the variant
 * parameters the user selects and the CI projects that run them; with `modules`, each plan's modules; with
 * `variants`, every variant parameter with the values the plans accept and the values the CI projects use.
 */
export function list(what: "plans" | "modules" | "variants"): string[] {
	const out: string[] = [];
	if (what === "variants") {
		const accepted = new Map<string, Set<string>>();
		const used = new Map<string, Set<string>>();
		for (const p of Object.values(plans)) {
			for (const [k, values] of Object.entries(p.variants)) {
				values.forEach((v) => add(accepted, k, v));
			}
		}
		for (const p of projects) {
			variantEntries(p.variant).forEach(([k, v]) => add(used, k, v));
		}
		for (const k of [...new Set([...accepted.keys(), ...used.keys()])].sort()) {
			out.push(`${k}: ${[...(accepted.get(k) ?? [])].join(", ")}`);
			out.push(`    ci projects: ${[...(used.get(k) ?? [])].join(", ")}`);
		}
		return out;
	}
	for (const [name, p] of Object.entries(plans)) {
		out.push(
			name,
			`    ${p.title}`,
			`    spec: ${p.spec} (${p.modules.length} module${p.modules.length === 1 ? "" : "s"})`,
		);
		const variants = Object.entries(p.variants).map(([k, values]) => `${k}=${values.join("|")}`);
		if (variants.length > 0) {
			out.push(`    variants: ${variants.join(" ")}`);
		}
		const ci = projects.filter((x) => x.plan === name).map((x) => x.name);
		if (ci.length > 0) {
			out.push(`    ci: ${ci.join(", ")}`);
		}
		if (what === "modules") {
			out.push(...p.modules.map((m) => `      ${m}`));
		}
	}
	return out;
}
