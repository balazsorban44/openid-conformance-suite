import { AbstractCondition, args, type JsonObject } from "../../framework/index.ts";
import { JWKUtil, ParseException, type JWK } from "../../util/JWKUtil.ts";

export abstract class AbstractGetSigningKey extends AbstractCondition {
	protected getSigningKey(name: string, jwks: JsonObject): JWK {
		let count = 0;
		let signingJwk: JWK | null = null;

		let jwkSet;
		try {
			jwkSet = JWKUtil.parseJWKSet(JSON.stringify(jwks));
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Failed to parse " + name + " jwks", e);
			}
			throw e;
		}

		for (const jwk of jwkSet.keys) {
			const use = jwk["use"];
			if (use != null && use !== "sig") {
				// skip any encryption keys
				continue;
			}
			count++;
			signingJwk = jwk;
		}

		if (count === 0) {
			throw this.error(
				"Did not find a key with 'use': 'sig' or no 'use' claim, no key available to sign jwt",
				args("jwks", jwks),
			);
		}
		if (count > 1) {
			throw this.error(
				"Expected only one signing JWK in the set. Please ensure the signing key is the only one in the jwks, or that other keys have a 'use' other than 'sig'.",
				args("jwks", jwks),
			);
		}

		return signingJwk as JWK;
	}
}
