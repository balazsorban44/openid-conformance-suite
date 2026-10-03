import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Checks that the discovery document this test will publish contains the provider metadata
 * OpenID Connect Discovery 1.0 section 3 marks as REQUIRED.
 *
 * <p>This is a check on the conformance suite's own behaviour when it acts as an OpenID
 * Provider: a relying party under test is entitled to reject a document that omits any of
 * these, in which case it never reaches the behaviour the test is actually about.
 *
 * <p>Only the presence of the fields is checked, not their contents. In particular the
 * additional requirement that {@code id_token_signing_alg_values_supported} contains RS256 is
 * deliberately not checked here, as a FAPI provider must not claim to support RS256.
 *
 * <p>Not applicable to a provider that publishes RFC 8414 authorization server metadata rather
 * than an OpenID Connect discovery document, nor to a CIBA-only provider (which has no
 * authorization endpoint and hence no response types).
 */
export class EnsureServerConfigurationHasRequiredOidcMetadata extends AbstractCondition {
	private static readonly REQUIRED_FIELDS: string[] = [
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	];

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;

		const missing: string[] = [];
		for (const field of EnsureServerConfigurationHasRequiredOidcMetadata.REQUIRED_FIELDS) {
			const value = server[field];
			if (value == null) {
				missing.push(field);
			}
		}

		if (missing.length > 0) {
			throw this.error(
				"The discovery document this test publishes is missing metadata OpenID Connect Discovery requires. " +
					"This is a bug in the conformance suite, please report it.",
				args("missing", missing, "server", server),
			);
		}

		this.logSuccess(
			"The discovery document contains all metadata required by OpenID Connect Discovery",
			args("server", server),
		);
		return env;
	}
}
