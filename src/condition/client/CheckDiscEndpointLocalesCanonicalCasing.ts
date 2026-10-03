import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonValue,
} from "../../framework/index.ts";
import { Bcp47LocaleValidation } from "../../util/Bcp47LocaleValidation.ts";

/**
 * Surfaces {@code ui_locales_supported} / {@code claims_locales_supported} entries whose casing
 * deviates from the BCP47 convention (lowercase language subtag, Title-case script, uppercase
 * region). Non-canonical casing is not a validity issue per RFC 5646 §2.1.1, but in practice
 * almost always indicates an implementer typo.
 *
 * <p>Wired in separately so the caller can choose WARNING severity; the underlying
 * {@link CheckDiscEndpointLocalesSyntax} stays a FAILURE for well-formedness and subtag-registry
 * membership.
 */
export class CheckDiscEndpointLocalesCanonicalCasing extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const issues: string[] = [];

		CheckDiscEndpointLocalesCanonicalCasing.walkArray(
			env.getElementFromObject("server", "ui_locales_supported"),
			"ui_locales_supported",
			issues,
		);
		CheckDiscEndpointLocalesCanonicalCasing.walkArray(
			env.getElementFromObject("server", "claims_locales_supported"),
			"claims_locales_supported",
			issues,
		);

		if (issues.length > 0) {
			throw this.error(
				"Authorization server locale tags deviate from BCP47 canonical casing (convention is lowercase language subtag, Title-case script, uppercase region); RFC 5646 §2.1.1 permits any case, but real-world implementations typically expect canonical casing.",
				args("issues", issues),
			);
		}

		this.logSuccess("All ui_locales_supported / claims_locales_supported entries use canonical BCP47 casing");
		return env;
	}

	private static walkArray(valuesEl: JsonValue | undefined, fieldName: string, issues: string[]): void {
		if (valuesEl == null || !isJsonArray(valuesEl)) {
			return;
		}
		const values = valuesEl;
		for (let i = 0; i < values.length; i++) {
			const entry = values[i];
			if (!OIDFJSON.isString(entry)) {
				continue;
			}
			const tag = OIDFJSON.getString(entry);
			const canonical = Bcp47LocaleValidation.nonCanonicalCasing(tag);
			if (canonical != null) {
				issues.push(`${fieldName}[${i}]: '${tag}' should be '${canonical}' to match BCP47 canonical casing`);
			}
		}
	}
}
