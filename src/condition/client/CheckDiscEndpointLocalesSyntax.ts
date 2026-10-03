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
import { Bcp47SubtagRegistry } from "../../util/Bcp47SubtagRegistry.ts";

/**
 * Validates {@code ui_locales_supported} and {@code claims_locales_supported} in authorization
 * server / OpenID Provider metadata. Each entry must be a well-formed BCP47 language tag with
 * subtags registered in the IANA Language Subtag Registry (via {@link Bcp47SubtagRegistry}).
 *
 * <p>Defined by RFC 8414 section 2 / OpenID Connect Discovery section 3. Duplicates are not
 * spec-forbidden here, so unlike OID4VCI {@code display.locale} validation the uniqueness rule
 * does not apply.
 *
 * <p>Non-canonical casing is conventional BCP47 style but not a validity issue per RFC 5646; it
 * is surfaced as a WARNING by {@link CheckDiscEndpointLocalesCanonicalCasing} instead.
 */
export class CheckDiscEndpointLocalesSyntax extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const issues: string[] = [];

		CheckDiscEndpointLocalesSyntax.validateLocalesArray(
			env.getElementFromObject("server", "ui_locales_supported"),
			"ui_locales_supported",
			issues,
		);
		CheckDiscEndpointLocalesSyntax.validateLocalesArray(
			env.getElementFromObject("server", "claims_locales_supported"),
			"claims_locales_supported",
			issues,
		);

		if (issues.length > 0) {
			throw this.error(
				"Invalid BCP47 language tag(s) in authorization server metadata",
				args("issues", issues, "language_subtag_registry_date", Bcp47SubtagRegistry.getInstance().getFileDate()),
			);
		}

		this.logSuccess(
			"All ui_locales_supported / claims_locales_supported entries are well-formed BCP47 tags with registered subtags",
		);
		return env;
	}

	private static validateLocalesArray(valuesEl: JsonValue | undefined, fieldName: string, issues: string[]): void {
		if (valuesEl == null) {
			return;
		}
		if (!isJsonArray(valuesEl)) {
			issues.push(`${fieldName}: expected JSON array, got ${JSON.stringify(valuesEl)}`);
			return;
		}
		const values = valuesEl;
		for (let i = 0; i < values.length; i++) {
			const entry = values[i];
			if (!OIDFJSON.isString(entry)) {
				issues.push(`${fieldName}[${i}]: expected string, got ${JSON.stringify(entry)}`);
				continue;
			}
			const tag = OIDFJSON.getString(entry);
			Bcp47LocaleValidation.validateSubtags(tag, `${fieldName}[${i}]`, issues);
		}
	}
}
