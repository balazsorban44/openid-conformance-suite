import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreateJwksUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["jwks_uri"] };

	override evaluate(env: Environment): Environment {
		let baseUrl = env.getString("base_url") as string;

		if (baseUrl.length === 0) {
			throw this.error("Base URL is empty");
		}

		// see https://gitlab.com/openid/conformance-suite/wikis/Developers/Build-&-Run#ciba-notification-endpoint
		const externalUrlOverride = env.getString("external_url_override");
		if (externalUrlOverride) {
			baseUrl = externalUrlOverride;
		}

		// calculate the redirect URI based on our given base URL
		const jwksUri = baseUrl + "/client1_jwks";

		env.putString("jwks_uri", jwksUri);

		this.logSuccess("Created JWKs URI", args("jwks_uri", jwksUri));

		return env;
	}
}
