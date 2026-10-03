import {
	AbstractCondition,
	args,
	isJsonObject,
	type Environment,
	type JsonObject,
	type JsonValue,
} from "../../framework/index.ts";
import { JWKUtil, ParseException, type JWKSet } from "../../util/JWKUtil.ts";

export abstract class AbstractExtractJWKsFromClientConfiguration extends AbstractCondition {
	protected extractJwks(
		env: Environment,
		jwks: JsonValue | undefined,
		jwksKey = "client_jwks",
		publicJwksKey = "client_public_jwks",
	): void {
		if (jwks == null) {
			throw this.error("Couldn't find JWKs in client configuration");
		} else if (!isJsonObject(jwks)) {
			throw this.error("Invalid JWKs in client configuration - JSON decode failed");
		}

		let parsed: JWKSet;

		try {
			parsed = JWKUtil.parseJWKSet(JSON.stringify(jwks));
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error(
					"Invalid JWKs in client configuration (private key is required), JWKSet.parse failed",
					e,
					args(jwksKey, jwks),
				);
			}
			throw e;
		}

		// parsed.toPublicJWKSet().toString()
		const pubObj: JsonObject = JWKUtil.getPublicJwksAsJsonObject(parsed);

		this.logSuccess("Extracted client JWK", args(jwksKey, jwks, publicJwksKey, pubObj));

		env.putObject(jwksKey, jwks);
		env.putObject(publicJwksKey, pubObj);
	}
}
