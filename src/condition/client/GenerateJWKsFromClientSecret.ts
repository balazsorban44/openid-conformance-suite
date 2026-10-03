import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { JWKUtil } from "../../util/JWKUtil.ts";

export class GenerateJWKsFromClientSecret extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };
	static override post: EnvironmentRequirements = { required: ["client_jwks"] };

	override evaluate(env: Environment): Environment {
		const clientSecret = env.getString("client", "client_secret");

		if (!clientSecret) {
			throw this.error("Couldn't find client secret");
		}

		let alg = env.getString("client", "client_secret_jwt_alg");
		if (!alg) {
			alg = "HS256"; // JWSAlgorithm.HS256.getName()
		}

		// generate a JWK Set for the client's secret
		const clientSecretBytes = Buffer.from(clientSecret, "utf8");

		//address issue #1196
		// client secret might be shorter than the required size to be used to sign
		let minSize: number;
		switch (alg.toUpperCase()) {
			case "HS256":
				minSize = 32;
				break;
			case "HS384":
				minSize = 48;
				break;
			default:
				minSize = 64;
				break;
		}
		if (clientSecretBytes.length < minSize) {
			throw this.error(
				"The client secret configured in the test plan is too short to sign a JWT with. The " +
					alg.toUpperCase() +
					" requires a secret with at least " +
					minSize +
					" bytes and the provided secret is " +
					clientSecretBytes.length +
					" bytes.",
			);
		}

		// new OctetSequenceKey.Builder(clientSecretBytes).algorithm(JWSAlgorithm.parse(alg)).keyUse(KeyUse.SIGNATURE).build()
		const jwk = {
			kty: "oct",
			use: "sig",
			alg: alg,
			// no key ID
			k: clientSecretBytes.toString("base64url"),
		};

		const jwks = { keys: [jwk] };

		const reparsed = JWKUtil.getPrivateJwksAsJsonObject(jwks);

		env.putObject("client_jwks", reparsed);

		this.logSuccess("Generated JWK Set from symmetric key", args("client_jwks", reparsed));

		return env;
	}
}
