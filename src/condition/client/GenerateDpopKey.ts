import { calculateJwkThumbprint } from "jose";
import {
	args,
	isJsonArray,
	jsonArrayContains,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
} from "../../framework/index.ts";
import type { JWK } from "../../util/JWKUtil.ts";
import { AbstractGenerateKey } from "./AbstractGenerateKey.ts";

export class GenerateDpopKey extends AbstractGenerateKey {
	static override pre: EnvironmentRequirements = { required: ["client", "server"] };

	override async evaluate(env: Environment): Promise<Environment> {
		let dpopSigningAlg = env.getString("client", "dpop_signing_alg");
		if (!dpopSigningAlg) {
			dpopSigningAlg = "PS256";
		}

		const dpopSupportedAlgs = env.getElementFromObject("server", "dpop_signing_alg_values_supported");
		if (null != dpopSupportedAlgs) {
			// UPSTREAM: Java casts to JsonArray without checking (ClassCastException for a non-array)
			if (!isJsonArray(dpopSupportedAlgs)) {
				throw new TypeError("dpop_signing_alg_values_supported cannot be cast to JsonArray");
			}
			if (!jsonArrayContains(dpopSupportedAlgs as JsonArray, dpopSigningAlg)) {
				dpopSigningAlg = OIDFJSON.getString(dpopSupportedAlgs[0]); // use first alg in dpop_signing_alg_values_supported if preference is not supported
			}
		}

		const keyJson = await this.createKeyForAlg(env, dpopSigningAlg);

		env.putObject("client", "dpop_private_jwk", keyJson);

		this.logSuccess("Generated dPOP JWKs", args("private_jwk", keyJson));

		return env;
	}

	// Generate kid using the thumbprint so that we don't have to parse the key again to get the thumbprint.

	protected override async onConfigureEc(b: JWK): Promise<JWK> {
		b["kid"] = await calculateJwkThumbprint(b, "sha256");
		return b;
	}

	protected override async onConfigureOkp(b: JWK): Promise<JWK> {
		b["kid"] = await calculateJwkThumbprint(b, "sha256");
		return b;
	}

	protected override async onConfigureRsa(b: JWK): Promise<JWK> {
		b["kid"] = await calculateJwkThumbprint(b, "sha256");
		return b;
	}
}
