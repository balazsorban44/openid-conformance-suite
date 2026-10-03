import { AbstractCondition, args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { JWKUtil } from "../../util/JWKUtil.ts";

/**
 * Fails if any <em>usable</em> key in {@code jwks_to_validate} cannot be parsed by the JOSE library.
 * This applies the checks the structural scan does not (e.g. the x5c bare-key-matches-certificate
 * check, and crypto-level validity). Keys the library cannot use (unknown key type, unsupported
 * curve, unrecognised algorithm) are skipped here - they are surfaced as a warning by
 * {@link WarnOnUnusableJwksKeys}, not failed.
 */
export class ParseUsableJwksKeys extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["jwks_to_validate"], strings: ["jwks_source_label"] };

	override evaluate(env: Environment): Environment {
		const label = env.getString("jwks_source_label");
		const jwks = env.getObject("jwks_to_validate") as JsonObject;

		const issues = JWKUtil.findUnparseableUsableKeys(jwks);
		if (issues.length > 0) {
			const first = issues[0]!;
			throw this.error(
				"The JWK set in " +
					label +
					" contains a key that should be usable but the JOSE " +
					"library cannot parse. The key at index " +
					first.index +
					" " +
					first.detail +
					".",
				args("jwks_source", label, "issues", JWKUtil.issuesToJson(issues)),
			);
		}

		this.logSuccess(
			"All usable keys in the JWK set in " + label + " parse successfully",
			args("jwks_source", label),
		);
		return env;
	}
}
