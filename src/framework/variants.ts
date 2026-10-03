/**
 * Port of the variant/ package: variant parameter "enums", the module-level variant annotations and
 * the parts of VariantService that resolve a test module instance for a variant selection.
 *
 * Java enums annotated with @VariantParameter become subclasses of VariantEnum:
 *
 *   export class ClientAuthType extends VariantEnum {
 *     static override readonly parameter = { name: "client_auth_type", displayName: "...", description: "..." };
 *     static readonly NONE = new ClientAuthType("NONE", "none");
 *     static readonly CLIENT_SECRET_BASIC = new ClientAuthType("CLIENT_SECRET_BASIC", "client_secret_basic");
 *   }
 *
 * The Java annotations on test module classes become a single static `variants` field, merged across the class
 * hierarchy (see collectVariantMetadata):
 *
 *   static override variants: ModuleVariantMetadata = {
 *     parameters: [ServerMetadata, ClientAuthType],                      // @VariantParameters
 *     notApplicable: [{ parameter: ClientAuthType, values: ["mtls"] }],  // @VariantNotApplicable
 *     configurationFields: [{ parameter: ServerMetadata, value: "static", configurationFields: ["server.issuer"] }],
 *     hidesConfigurationFields: [...],                                   // @VariantHidesConfigurationFields
 *     setup: [{ parameter: ClientAuthType, value: "none", method: "setupNone" }], // @VariantSetup methods
 *   };
 */

export interface VariantParameterInfo {
	name: string;
	displayName: string;
	description?: string;
	defaultValue?: string;
	sortOrder?: number;
}

export abstract class VariantEnum {
	/** The @VariantParameter annotation */
	static readonly parameter: VariantParameterInfo;

	/** Java enum constant name, e.g. CLIENT_SECRET_BASIC */
	readonly enumName: string;
	/** Java toString() value, e.g. client_secret_basic */
	readonly value: string;

	protected constructor(enumName: string, value?: string) {
		this.enumName = enumName;
		this.value = value ?? enumName.toLowerCase();
	}

	toString(): string {
		return this.value;
	}

	toJSON(): string {
		return this.value;
	}

	/** Java: Enum.name() */
	name(): string {
		return this.enumName;
	}

	/** All constants of this enum, in declaration order */
	static values<T extends VariantEnum>(this: VariantEnumClass<T>): T[] {
		const out: T[] = [];
		for (const key of Object.getOwnPropertyNames(this)) {
			const v = (this as unknown as Record<string, unknown>)[key];
			if (v instanceof (this as unknown as abstract new (...a: never[]) => T)) {
				out.push(v as T);
			}
		}
		return out;
	}

	/** Java: Enum.valueOf(name) / the string form used in test plans ("code id_token") */
	static fromString<T extends VariantEnum>(this: VariantEnumClass<T>, value: string): T {
		for (const v of this.values()) {
			if (v.value === value || v.enumName === value) {
				return v;
			}
		}
		throw new Error(`Invalid value '${value}' for variant parameter '${this.parameter.name}' (${this.name})`);
	}

	static hasValue<T extends VariantEnum>(this: VariantEnumClass<T>, value: string): boolean {
		return this.values().some((v) => v.value === value);
	}
}

export interface VariantEnumClass<T extends VariantEnum = VariantEnum> {
	readonly parameter: VariantParameterInfo;
	readonly name: string;
	values(): T[];
	fromString(value: string): T;
	hasValue(value: string): boolean;
	prototype: T;
}

export interface VariantNotApplicable {
	parameter: VariantEnumClass;
	values: string[];
}

export interface VariantApplicableOnly {
	parameter: VariantEnumClass;
	values: string[];
}

export interface VariantNotApplicableWhen {
	parameter: VariantEnumClass;
	/** Use ["*"] to indicate all values of the parameter */
	values: string[];
	whenParameter: VariantEnumClass;
	hasValues: string[];
}

export interface VariantConfigurationFields {
	parameter: VariantEnumClass;
	value: string;
	configurationFields: string[];
}

export interface VariantSetup {
	parameter: VariantEnumClass;
	value: string;
	/** Name of the (public) method on the module to call */
	method: string;
}

export interface ModuleVariantMetadata {
	parameters?: VariantEnumClass[];
	notApplicable?: VariantNotApplicable[];
	applicableOnly?: VariantApplicableOnly[];
	notApplicableWhen?: VariantNotApplicableWhen[];
	configurationFields?: VariantConfigurationFields[];
	hidesConfigurationFields?: VariantConfigurationFields[];
	setup?: VariantSetup[];
	/** @ConfigurationFields on the class (not variant specific) */
	plainConfigurationFields?: string[];
}

/**
 * Walk the prototype chain and merge every class's own `static variants` (Java: annotations are inherited
 * and @Repeatable ones compose across the hierarchy).
 */
export function collectVariantMetadata(moduleClass: Function): Required<ModuleVariantMetadata> {
	const chain: Function[] = [];
	let c: Function | null = moduleClass;
	while (c && c !== Function.prototype && c !== Object) {
		chain.push(c);
		c = Object.getPrototypeOf(c) as Function | null;
	}
	chain.reverse(); // base class first
	const out: Required<ModuleVariantMetadata> = {
		parameters: [],
		notApplicable: [],
		applicableOnly: [],
		notApplicableWhen: [],
		configurationFields: [],
		hidesConfigurationFields: [],
		setup: [],
		plainConfigurationFields: [],
	};
	for (const cls of chain) {
		if (!Object.prototype.hasOwnProperty.call(cls, "variants")) {
			continue;
		}
		const v = (cls as unknown as { variants?: ModuleVariantMetadata }).variants;
		if (!v) {
			continue;
		}
		for (const p of v.parameters ?? []) {
			if (!out.parameters.includes(p)) {
				out.parameters.push(p);
			}
		}
		out.notApplicable.push(...(v.notApplicable ?? []));
		out.applicableOnly.push(...(v.applicableOnly ?? []));
		out.notApplicableWhen.push(...(v.notApplicableWhen ?? []));
		out.configurationFields.push(...(v.configurationFields ?? []));
		out.hidesConfigurationFields.push(...(v.hidesConfigurationFields ?? []));
		out.setup.push(...(v.setup ?? []));
		out.plainConfigurationFields.push(...(v.plainConfigurationFields ?? []));
	}
	return out;
}

/**
 * Port of variant/VariantSelection.java: the user's selected variant values, keyed by variant parameter name
 * (e.g. { client_auth_type: "client_secret_basic", response_type: "code" }).
 */
export class VariantSelection {
	private readonly variant: Record<string, string>;

	constructor(variant: Record<string, string>) {
		this.variant = { ...variant };
	}

	/** Parse the command line form `[client_auth_type=mtls][response_type=code]` */
	static fromBracketString(s: string): VariantSelection {
		const out: Record<string, string> = {};
		for (const m of s.matchAll(/\[([^\]=]+)=([^\]]*)\]/g)) {
			out[m[1]] = m[2];
		}
		return new VariantSelection(out);
	}

	getVariant(): Record<string, string> {
		return { ...this.variant };
	}

	getVariantParameterValue(parameterClass: VariantEnumClass): string | undefined {
		return this.variant[parameterClass.parameter.name];
	}

	has(parameterClass: VariantEnumClass): boolean {
		return parameterClass.parameter.name in this.variant;
	}

	/** The `[k=v][k2=v2]` form used by the upstream CI runner and our test names (sorted by key) */
	toBracketString(): string {
		return Object.keys(this.variant)
			.sort()
			.map((k) => `[${k}=${this.variant[k]}]`)
			.join("");
	}

	toJSON(): Record<string, string> {
		return { ...this.variant };
	}
}

/** The resolved variant values for a module instance: parameter class -> enum constant */
export type VariantMap = Map<VariantEnumClass, VariantEnum>;

/**
 * Check whether a value of a parameter is excluded for a module by @VariantNotApplicable / @VariantApplicableOnly /
 * @VariantNotApplicableWhen.
 */
export function isVariantValueApplicable(
	meta: Required<ModuleVariantMetadata>,
	parameter: VariantEnumClass,
	value: string,
	selection: VariantSelection,
): boolean {
	for (const na of meta.notApplicable) {
		if (na.parameter === parameter && na.values.includes(value)) {
			return false;
		}
	}
	for (const ao of meta.applicableOnly) {
		if (ao.parameter === parameter && !ao.values.includes(value)) {
			return false;
		}
	}
	for (const naw of meta.notApplicableWhen) {
		if (naw.parameter !== parameter) {
			continue;
		}
		const whenValue = selection.getVariantParameterValue(naw.whenParameter);
		if (whenValue !== undefined && naw.hasValues.includes(whenValue)) {
			if (naw.values.includes("*") || naw.values.includes(value)) {
				return false;
			}
		}
	}
	return true;
}
