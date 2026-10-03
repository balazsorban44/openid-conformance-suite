import { AbstractCondition, args, type Environment } from "../../framework/index.ts";
import { JWKUtil, type JWK } from "../../util/JWKUtil.ts";

export abstract class AbstractGenerateClientJWKs extends AbstractCondition {
	static readonly DEFAULT_KEY_SIZE = 2048;

	/** Publish a pre-built client signing JWK as `client_jwks` +
	 *  `client_public_jwks`. Subclasses that build the JWK themselves
	 *  (e.g. from a pre-generated key pool) can call this directly. */
	protected publishClientJWKs(env: Environment, key: JWK): Environment {
		const keys = { keys: [key] };

		const jwks = JWKUtil.getPrivateJwksAsJsonObject(keys);
		const publicJwks = JWKUtil.getPublicJwksAsJsonObject(keys);

		env.putObject("client_jwks", jwks);
		env.putObject("client_public_jwks", publicJwks);

		this.logSuccess("Generated client JWKs", args("client_jwks", jwks, "public_client_jwks", publicJwks));

		return env;
	}
}
