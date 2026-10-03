import {
	AbstractCondition,
	args,
	isJsonObject,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Copies the JWK set to be validated from its source location into the common
 * {@code jwks_to_validate} environment key, so the generic JWKS-validation conditions can run
 * against any source. The source object key, an optional dot-separated path within it, and a
 * human-readable label are supplied by the caller (typically {@link net.openid.conformance.sequence.ValidateJwksSequence})
 * as environment strings.
 */
export class MapJwksToValidationLocation extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["jwks_validation_source_key", "jwks_source_label"] };
	static override post: EnvironmentRequirements = { required: ["jwks_to_validate"] };

	override evaluate(env: Environment): Environment {
		const sourceKey = env.getString("jwks_validation_source_key") as string;
		const sourcePath = env.getString("jwks_validation_source_path");
		const label = env.getString("jwks_source_label");

		let jwks: JsonObject | null;
		if (sourcePath == null || sourcePath === "") {
			jwks = env.getObject(sourceKey);
		} else {
			const el = env.getElementFromObject(sourceKey, sourcePath);
			jwks = el != null && isJsonObject(el) ? el : null;
		}

		if (jwks == null) {
			throw this.error(
				"Could not find a JWK set to validate for " + label,
				args("source_key", sourceKey, "source_path", sourcePath == null ? "" : sourcePath),
			);
		}

		env.putObject("jwks_to_validate", jwks);
		this.logSuccess("Selected the JWK set in " + label + " for validation", args("jwks", jwks));
		return env;
	}
}
