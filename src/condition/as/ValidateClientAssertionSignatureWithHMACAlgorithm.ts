import { args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { ParseException } from "../../util/JWKUtil.ts";
import { isJOSEException } from "../../util/nimbus/errors.ts";
import { parseSignedJWT } from "../../util/nimbus/jwt.ts";
import { AbstractVerifyJwsSignature } from "../client/AbstractVerifyJwsSignature.ts";

export class ValidateClientAssertionSignatureWithHMACAlgorithm extends AbstractVerifyJwsSignature {
	static override pre: EnvironmentRequirements = { required: ["client", "client_assertion"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const clientAssertionString = env.getString("client_assertion", "value") as string;
		const clientSecret = env.getString("client", "client_secret") as string;

		try {
			const jwt = parseSignedJWT(clientAssertionString);
			const isValid = await this.verifyHMACSignature(jwt, clientSecret);
			if (isValid) {
				this.logSuccess("Client assertion signature is valid");
				return env;
			} else {
				throw this.error(
					"Client assertion signature is invalid",
					args("client_assertion", clientAssertionString, "client_secret", clientSecret),
				);
			}
		} catch (ex) {
			if (isJOSEException(ex)) {
				throw this.error(
					"Failed to validate client assertion",
					ex,
					args("client_assertion", clientAssertionString, "client_secret", clientSecret),
				);
			}
			if (ex instanceof ParseException) {
				throw this.error("Invalid client assertion", ex, args("client_assertion", clientAssertionString));
			}
			throw ex;
		}
	}
}
