import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JWKUtil } from "../../util/JWKUtil.ts";

/**
 * Reports (as a warning, when the caller sets the result to WARNING) keys in {@code jwks_to_validate}
 * that the JOSE library cannot use: an unsupported key type, an unsupported curve, or an unrecognised
 * algorithm. Such keys are legitimate for a counterparty to publish - a recipient ignores keys it
 * cannot use (RFC 7517 section 5) - but are flagged so they remain visible in the test log rather
 * than being silently skipped.
 */
export class WarnOnUnusableJwksKeys extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["jwks_to_validate"], strings: ["jwks_source_label"] };

	override evaluate(env: Environment): Environment {
		const label = env.getString("jwks_source_label");
		const jwks = env.getObject("jwks_to_validate") as JsonObject;

		const issues = JWKUtil.findUnusableKeys(jwks);
		if (issues.length > 0) {
			const first = issues[0]!;
			throw this.error(
				"The JWK set in " +
					label +
					" contains " +
					issues.length +
					" key(s) that the test suite cannot use (e.g. unsupported key type, curve, or " +
					"algorithm). The key at index " +
					first.index +
					" " +
					first.detail +
					".",
				args("jwks_source", label, "issues", JWKUtil.issuesToJson(issues)),
			);
		}

		this.logSuccess(
			"All keys in the JWK set in " + label + " use a supported key type, curve and algorithm",
			args("jwks_source", label),
		);
		return env;
	}
}
