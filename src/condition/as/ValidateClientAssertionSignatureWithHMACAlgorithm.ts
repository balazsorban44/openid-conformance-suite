import { errors } from "jose";
import { args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { JOSEException } from "../../util/JWEUtil.ts";
import { ParseException } from "../../util/JWKUtil.ts";
import { JWTUtil, type JWT } from "../../util/JWTUtil.ts";
import { AbstractVerifyJwsSignature } from "../client/AbstractVerifyJwsSignature.ts";

/**
 * Nimbus SignedJWT.parse(s): like JWTParser.parse, but only accepts a JWS.
 * @throws ParseException
 */
function parseSignedJWT(s: string): JWT {
	const jwt = JWTUtil.parseJWT(s);
	if (jwt.type !== "signed") {
		if (jwt.parts.length !== 3) {
			throw new ParseException("Unexpected number of Base64URL parts, must be three");
		}
		throw new ParseException("Invalid JWS header: Not a JWS header");
	}
	return jwt;
}

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
			if (ex instanceof JOSEException || ex instanceof errors.JOSEError) {
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
