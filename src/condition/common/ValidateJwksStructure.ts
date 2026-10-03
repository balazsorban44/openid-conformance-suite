import {
	AbstractCondition,
	args,
	isJsonArray,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JWKUtil } from "../../util/JWKUtil.ts";

/**
 * Fails if the JWK set in {@code jwks_to_validate} is structurally invalid: not a JWK set object,
 * a key missing the members required for its key type, or a coordinate value that is not unpadded
 * base64url. Keys whose key type the JOSE library does not recognise are not failed here - they are
 * surfaced as a warning by {@link WarnOnUnusableJwksKeys}.
 */
export class ValidateJwksStructure extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["jwks_to_validate"], strings: ["jwks_source_label"] };

	override evaluate(env: Environment): Environment {
		const label = env.getString("jwks_source_label");
		const jwks = env.getObject("jwks_to_validate") as JsonObject;

		const keys = jwks["keys"];
		if (keys == null || !isJsonArray(keys)) {
			throw this.error(
				"The JWK set in " + label + " does not contain a 'keys' array",
				args("jwks_source", label, "jwks", jwks),
			);
		}

		const issues = JWKUtil.findStructurallyInvalidKeys(jwks);
		if (issues.length > 0) {
			const first = issues[0]!;
			throw this.error(
				"The JWK set in " +
					label +
					" is structurally invalid. The key at index " +
					first.index +
					" " +
					first.detail +
					".",
				args("jwks_source", label, "issues", JWKUtil.issuesToJson(issues)),
			);
		}

		this.logSuccess("The JWK set in " + label + " is structurally valid", args("jwks_source", label));
		return env;
	}
}
