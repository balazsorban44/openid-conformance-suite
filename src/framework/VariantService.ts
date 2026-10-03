import type { AbstractTestModule } from "./AbstractTestModule.ts";
import { ModuleListEntry, type TestPlanClass } from "./plan.ts";
import type { TestModuleClass } from "./TestModule.ts";
import {
	collectVariantMetadata,
	isVariantValueApplicable,
	VariantSelection,
	type VariantEnumClass,
	type VariantMap,
} from "./variants.ts";

/** One module to run, with its fully resolved variant selection (port of VariantService.TestPlanModuleWithVariant) */
export interface PlanModule {
	moduleClass: TestModuleClass<AbstractTestModule>;
	testName: string;
	/** The complete variant selection the module runs with (user selection + the plan's fixed variants) */
	variant: VariantSelection;
	/** Only the variants fixed by the plan definition */
	variantFromPlanDefinition: VariantSelection;
}

export class VariantConfigurationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "VariantConfigurationError";
	}
}

/**
 * Port of the parts of variant/VariantService.java needed to expand a plan into module instances and to
 * instantiate a module with a variant selection.
 */
export const VariantService = {
	/**
	 * The variant parameters a module declares (merged across its class hierarchy)
	 */
	parametersOf(moduleClass: TestModuleClass): VariantEnumClass[] {
		return collectVariantMetadata(moduleClass).parameters;
	},

	/**
	 * Expand a test plan into the list of modules to run for the user's variant selection.
	 */
	expandPlan(planClass: TestPlanClass, selection: VariantSelection): PlanModule[] {
		const plan = new planClass();
		let entries = plan.testModulesWithVariants();
		if (entries == null) {
			entries = [new ModuleListEntry((planClass.meta.testModules ?? []) as TestModuleClass[], [])];
		}
		const out: PlanModule[] = [];
		for (const entry of entries) {
			// applicableWhen: all conditions must match (AND), each condition matches any of its values (OR)
			const applicable = entry.applicableWhen.every((c) => {
				const v = selection.getVariantParameterValue(c.parameter);
				return v !== undefined && c.values.includes(v);
			});
			if (!applicable) {
				continue;
			}
			for (const moduleClass of entry.testModules) {
				const meta = collectVariantMetadata(moduleClass);
				const fixed: Record<string, string> = {};
				let skipModule = false;
				for (const v of entry.variant) {
					if (!meta.parameters.includes(v.key)) {
						if (entry.optionalVariants.has(v.key)) {
							continue;
						}
						throw new VariantConfigurationError(
							`Test plan '${planClass.name}' module '${moduleClass.name}' requests variant '${v.key.name}' which the test module does not declare`,
						);
					}
					if (!v.key.hasValue(v.value)) {
						throw new VariantConfigurationError(
							`Test plan '${planClass.name}' module '${moduleClass.name}' requests unknown value '${v.value}' for variant '${v.key.name}'`,
						);
					}
					if (!isVariantValueApplicable(meta, v.key, v.value, selection)) {
						throw new VariantConfigurationError(
							`Test plan '${planClass.name}' module '${moduleClass.name}' requests variant '${v.key.name}' for a value ('${v.value}') the test module excludes via notApplicable / applicableOnly`,
						);
					}
					fixed[v.key.parameter.name] = v.value;
				}
				if (skipModule) {
					continue;
				}
				const full = new VariantSelection({ ...selection.getVariant(), ...fixed });
				// a module is dropped from the plan when the user's selection picks a value it excludes
				let excluded = false;
				for (const p of meta.parameters) {
					const value = full.getVariantParameterValue(p);
					if (value === undefined) {
						continue;
					}
					if (!isVariantValueApplicable(meta, p, value, full)) {
						excluded = true;
						break;
					}
				}
				if (excluded) {
					continue;
				}
				out.push({
					moduleClass: moduleClass as TestModuleClass<AbstractTestModule>,
					testName: (moduleClass.meta as { testName: string }).testName,
					variant: full,
					variantFromPlanDefinition: new VariantSelection(fixed),
				});
			}
		}
		return out;
	},

	/**
	 * Build the module's VariantMap from a selection (checking every declared parameter has a value) and run
	 * its @VariantSetup methods. Returns the resolved map; the caller instantiates and calls setVariant.
	 */
	resolveVariantMap(moduleClass: TestModuleClass, selection: VariantSelection): VariantMap {
		const meta = collectVariantMetadata(moduleClass);
		const map: VariantMap = new Map();
		for (const p of meta.parameters) {
			let value = selection.getVariantParameterValue(p);
			if (value === undefined) {
				value = p.parameter.defaultValue;
			}
			if (value === undefined || value === "") {
				throw new VariantConfigurationError(
					`Missing value for variant parameter '${p.parameter.name}' required by test module '${moduleClass.name}' (allowed: ${p
						.values()
						.map((v) => v.toString())
						.join(", ")})`,
				);
			}
			if (!p.hasValue(value)) {
				throw new VariantConfigurationError(
					`Invalid value '${value}' for variant parameter '${p.parameter.name}' (allowed: ${p
						.values()
						.map((v) => v.toString())
						.join(", ")})`,
				);
			}
			if (!isVariantValueApplicable(meta, p, value, selection)) {
				throw new VariantConfigurationError(
					`Test module '${moduleClass.name}' does not support '${p.parameter.name}=${value}'`,
				);
			}
			map.set(p, p.fromString(value));
		}
		return map;
	},

	/**
	 * Instantiate a module for the given selection: sets the variant map and invokes the @VariantSetup methods.
	 */
	newInstance<T extends AbstractTestModule>(moduleClass: TestModuleClass<T>, selection: VariantSelection): T {
		const meta = collectVariantMetadata(moduleClass);
		const map = VariantService.resolveVariantMap(moduleClass, selection);
		const instance = new moduleClass();
		instance.setVariant(map);
		for (const setup of meta.setup) {
			const value = map.get(setup.parameter);
			if (value != null && value.toString() === setup.value) {
				const fn = (instance as unknown as Record<string, unknown>)[setup.method];
				if (typeof fn !== "function") {
					throw new VariantConfigurationError(
						`Variant setup method '${setup.method}' not found on ${moduleClass.name}`,
					);
				}
				(fn as () => void).call(instance);
			}
		}
		return instance;
	},
};
