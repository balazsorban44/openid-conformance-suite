import type { TestModuleClass } from "./TestModule.ts";
import type { VariantEnum, VariantEnumClass, VariantSelection } from "./variants.ts";

/** Port of plan/TestPlan.java ProfileNames */
export const ProfileNames = {
	rptest: "Test a Relying Party / OAuth2 Client",
	rplogouttest: "Test a Relying Party / OAuth2 Client Logout Support",
	optest: "Test an OpenID Provider / Authorization Server",
	ssftest: "Test Shared Signals Framework Support",
	ekyctest: "Test an eKYC & IDA OpenID Provider",
	vciissuer: "Test a OpenID4VCI issuer",
	vciwallet: "Test a OpenID4VCI wallet",
	wallettest: "Test a OpenID4VP wallet",
	verifierTest: "Test a OpenID4VP Verifier",
	federationTest: "Test an OpenID Federation entity",
	authzenTest: "Test an AuthZEN PDP server",
} as const;

/** Port of plan/TestPlan.java SpecFamilyNames */
export const SpecFamilyNames = {
	authzen: "AuthZEN",
	ekyc: "eKYC & Identity Assurance",
	fapi1Advanced: "FAPI1 Advanced",
	fapi2SecurityProfile: "FAPI2 Security Profile",
	fapi2MessageSigning: "FAPI2 Message Signing",
	fapiCiba: "FAPI-CIBA",
	federation: "OpenID Federation",
	oid4vci: "OID4VCI",
	oid4vp: "OID4VP",
	oidcc: "OpenID Connect Core",
	oidccLogout: "OpenID Connect Logout",
	oidccSessionManagement: "OpenID Connect Session Management",
	ssf: "Shared Signals Framework",
} as const;

/** Port of plan/PublishTestPlan.java */
export interface PublishTestPlan {
	testPlanName: string;
	displayName: string;
	profile: string;
	specFamily?: string;
	specVersion?: string;
	summary?: string;
	/** Modules listed directly in the annotation (alternative to testModulesWithVariants()) */
	testModules?: TestModuleClass[];
	configurationFields?: string[];
}

/** A set of variants and values to use to run a particular test module. */
export class Variant {
	readonly key: VariantEnumClass;
	readonly value: string;

	constructor(key: VariantEnumClass, value: string | VariantEnum) {
		this.key = key;
		this.value = typeof value === "string" ? value : value.toString();
	}
}

/** A condition that must be met for a ModuleListEntry to be applicable. */
export class VariantCondition {
	readonly parameter: VariantEnumClass;
	readonly values: string[];

	constructor(parameter: VariantEnumClass, ...values: string[]) {
		this.parameter = parameter;
		this.values = values;
	}
}

/** A holder for one or more test modules and the variants they should be run with */
export class ModuleListEntry {
	readonly testModules: TestModuleClass[];
	readonly variant: Variant[];
	readonly applicableWhen: VariantCondition[];
	readonly optionalVariants: Set<VariantEnumClass>;

	constructor(
		testModules: TestModuleClass[],
		variant: Variant[],
		applicableWhenOrOptional?: VariantCondition[] | Set<VariantEnumClass>,
		optionalVariants?: Set<VariantEnumClass>,
	) {
		this.testModules = testModules;
		this.variant = variant;
		if (applicableWhenOrOptional instanceof Set) {
			this.applicableWhen = [];
			this.optionalVariants = applicableWhenOrOptional;
		} else {
			this.applicableWhen = applicableWhenOrOptional ?? [];
			this.optionalVariants = optionalVariants ?? new Set();
		}
	}
}

/**
 * Port of plan/TestPlan.java
 *
 * A collection of test modules intended to be run with a single test configuration. Concrete plans declare
 * `static readonly meta: PublishTestPlan` and override testModulesWithVariants() and/or certificationProfileName().
 */
export abstract class TestPlan {
	static readonly meta: PublishTestPlan;

	/** Override to define test modules with specific variant combinations; null to use meta.testModules */
	testModulesWithVariants(): ModuleListEntry[] | null {
		return null;
	}

	/** Override to define a certification profile name for the given variant selection. */
	certificationProfileName(_variant: VariantSelection): string[] {
		return [];
	}
}

export interface TestPlanClass {
	new (): TestPlan;
	readonly name: string;
	readonly meta: PublishTestPlan;
}
