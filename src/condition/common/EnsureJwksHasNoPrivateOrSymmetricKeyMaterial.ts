import { AbstractCondition, args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { JWKUtil } from "../../util/JWKUtil.ts";

/**
 * Fails if the JWK set in {@code jwks_to_validate} contains any private or symmetric key material.
 * Detection is a raw JSON member scan (see {@link JWKUtil#findPrivateOrSymmetricKeyMembers}), so a
 * private key the JOSE library cannot parse - e.g. on an unsupported curve, or with an unknown key
 * type - is still caught (the library would otherwise silently drop or fail to inspect it).
 */
export class EnsureJwksHasNoPrivateOrSymmetricKeyMaterial extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["jwks_to_validate"], strings: ["jwks_source_label"] };

	override evaluate(env: Environment): Environment {
		const label = env.getString("jwks_source_label");
		const jwks = env.getObject("jwks_to_validate") as JsonObject;

		const issues = JWKUtil.findPrivateOrSymmetricKeyMembers(jwks);
		if (issues.length > 0) {
			const first = issues[0]!;
			throw this.error(
				"The JWK set in " +
					label +
					" contains private or symmetric key material; " +
					"a published JWK set must contain public keys only. The key at index " +
					first.index +
					" " +
					first.detail +
					".",
				args("jwks_source", label, "issues", JWKUtil.issuesToJson(issues)),
			);
		}

		this.logSuccess("The JWK set in " + label + " contains only public key material", args("jwks_source", label));
		return env;
	}
}
