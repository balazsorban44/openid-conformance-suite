import { args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { ParseException } from "../../util/JWKUtil.ts";
import { parseSignedJWT } from "../../util/nimbus/jwt.ts";
import { AbstractVerifyJwsSignature } from "../client/AbstractVerifyJwsSignature.ts";

/**
 * token_endpoint_auth_signing_alg
 * ...
 * All Token Requests using these authentication methods from this Client MUST be rejected,
 * if the JWT is not signed with this algorithm
 * ...
 */
export class EnsureClientAssertionSignatureAlgorithmMatchesRegistered extends AbstractVerifyJwsSignature {
	static override pre: EnvironmentRequirements = { required: ["client", "client_assertion"] };

	override evaluate(env: Environment): Environment {
		const clientAssertionString = env.getString("client_assertion", "value") as string;
		try {
			const jwt = parseSignedJWT(clientAssertionString);
			const expectedAlgName = env.getString("client", "token_endpoint_auth_signing_alg");
			if (expectedAlgName != null) {
				const expectedAlg = expectedAlgName;
				const actualAlg = jwt.header["alg"] as string;
				if (expectedAlg === actualAlg) {
					this.logSuccess(
						"Client assertion is signed using the registered token_endpoint_auth_signing_alg algorithm",
						args("algorithm", expectedAlgName),
					);
				} else {
					throw this.error(
						"Client assertion is not signed using the registered token_endpoint_auth_signing_alg algorithm.",
						args("expected", expectedAlgName, "actual", actualAlg),
					);
				}
			} else {
				this.log("token_endpoint_auth_signing_alg is not set for the client, any supported algorithm can be used");
			}
		} catch (ex) {
			if (ex instanceof ParseException) {
				throw this.error("Invalid client assertion", ex, args("client_assertion", clientAssertionString));
			}
			throw ex;
		}
		return env;
	}
}
