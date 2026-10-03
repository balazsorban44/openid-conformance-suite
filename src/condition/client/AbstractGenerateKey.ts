import { errors } from "jose";
import { AbstractCondition, args, type Environment, type JsonObject } from "../../framework/index.ts";
import { JWKUtil, type JWK } from "../../util/JWKUtil.ts";
import { PreGeneratedJwks } from "../../util/PreGeneratedJwks.ts";

export abstract class AbstractGenerateKey extends AbstractCondition {
	static readonly RSA_KEY_SIZE = 2048;

	protected async createKeyForAlg(env: Environment, alg: string): Promise<JsonObject> {
		const key = await this.createJwkForAlg(env, alg);
		// JsonParser.parseString(key.toJSONString())
		return JWKUtil.parseJWK(key);
	}

	/**
	 * The builders (Nimbus `ECKey.Builder` etc.) are the JSON JWKs: the key from {@link PreGeneratedJwks} with
	 * `use` and `alg` set. Async because the extension points may compute a thumbprint (jose is async).
	 */
	protected async createJwkForAlg(env: Environment, alg: string): Promise<JWK> {
		try {
			switch (alg) {
				case "ES256":
					return await this.onConfigureEc(
						AbstractGenerateKey.withUseAndAlg(PreGeneratedJwks.nextEcKey(env, "P-256"), "ES256"),
					);
				case "EdDSA":
					return await this.onConfigureOkp(
						AbstractGenerateKey.withUseAndAlg(PreGeneratedJwks.nextOkpKey(env, "Ed25519"), "EdDSA"),
					);
				case "Ed25519":
					return await this.onConfigureOkp(
						AbstractGenerateKey.withUseAndAlg(PreGeneratedJwks.nextOkpKey(env, "Ed25519"), "Ed25519"),
					);
				case "PS256":
					return await this.onConfigureRsa(
						AbstractGenerateKey.withUseAndAlg(
							PreGeneratedJwks.nextRsaKey(env, AbstractGenerateKey.RSA_KEY_SIZE),
							"PS256",
						),
					);
				default:
					throw this.error("Failed to generate key for alg", args("alg", alg));
			}
		} catch (e) {
			if (e instanceof errors.JOSEError) {
				throw this.error("Failed to build key for alg " + alg, e);
			}
			throw e;
		}
	}

	/** `.keyUse(KeyUse.SIGNATURE).algorithm(alg)` on a builder */
	private static withUseAndAlg(key: JWK, alg: string): JWK {
		key["use"] = "sig";
		key["alg"] = alg;
		return key;
	}

	/** Extension point: applied to the EC builder before `build()` (e.g.
	 *  to add `keyIDFromThumbprint(true)`). Default is a no-op. */
	protected onConfigureEc(b: JWK): JWK | Promise<JWK> {
		return b;
	}

	/** Extension point for OKP builders; see {@link AbstractGenerateKey.onConfigureEc}. */
	protected onConfigureOkp(b: JWK): JWK | Promise<JWK> {
		return b;
	}

	/** Extension point for RSA builders; see {@link AbstractGenerateKey.onConfigureEc}. */
	protected onConfigureRsa(b: JWK): JWK | Promise<JWK> {
		return b;
	}
}
