import { modules, plans } from "../registry.ts";
import { expandPlan } from "../framework/VariantService.ts";
import { collectVariantMetadata, VariantSelection } from "../framework/variants.ts";

/**
 * `openid-conformance list`: the plans (with their user-selectable variants), the test modules or the variant
 * parameters, read from the plan registry (src/registry.ts).
 */
export function listRegistry(what: "plans" | "modules" | "variants"): string[] {
	const out: string[] = [];
	if (what === "modules") {
		for (const m of modules) {
			out.push(`${m.meta?.testName}\n    ${m.meta?.displayName}`);
		}
		return out;
	}
	if (what === "variants") {
		const seen = new Map<string, Set<string>>();
		for (const m of modules) {
			for (const v of collectVariantMetadata(m).parameters) {
				seen.set(v.parameter.name, new Set(v.values().map(String)));
			}
		}
		for (const [k, vals] of seen) {
			out.push(`${k}: ${[...vals].join(", ")}`);
		}
		return out;
	}
	for (const p of plans) {
		out.push(`${p.meta.testPlanName}\n    ${p.meta.displayName}`);
		const params = new Set<string>();
		for (const m of expandPlan(p, new VariantSelection({}))) {
			for (const v of collectVariantMetadata(m.moduleClass).parameters) {
				if (!m.variantFromPlanDefinition.has(v)) {
					params.add(`${v.parameter.name}=${v.values().map(String).join("|")}`);
				}
			}
		}
		if (params.size > 0) {
			out.push(`    variants: ${[...params].join(" ")}`);
		}
	}
	return out;
}
