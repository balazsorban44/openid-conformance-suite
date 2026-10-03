import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractExtractJWKsFromClientConfiguration } from "./AbstractExtractJWKsFromClientConfiguration.ts";

// Extracts the JWKS from the 'client' element that 'GetStaticClientConfiguration' added to the environment root
export class ExtractJWKsFromStaticClientConfiguration extends AbstractExtractJWKsFromClientConfiguration {
	static override pre: EnvironmentRequirements = { required: ["client"] };
	static override post: EnvironmentRequirements = { required: ["client_jwks", "client_public_jwks"] };

	override evaluate(env: Environment): Environment {
		// bump the client's internal JWK up to the root
		const jwks = env.getElementFromObject("client", "jwks");
		this.extractJwks(env, jwks);

		return env;
	}
}
