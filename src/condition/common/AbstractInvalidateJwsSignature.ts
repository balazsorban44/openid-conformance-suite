import { AbstractCondition, args, type Environment } from "../../framework/index.ts";
import { JWTUtil, ParseException } from "../../util/JWTUtil.ts";

export abstract class AbstractInvalidateJwsSignature extends AbstractCondition {
	invalidateSignature(env: Environment, environmentKey: string): Environment {
		const jwtString = env.getString(environmentKey) as string;

		const invalidJwtString = this.invalidateSignatureString(environmentKey, jwtString);

		env.putString(environmentKey, invalidJwtString);

		this.log("Made the " + environmentKey + " signature invalid", args(environmentKey, invalidJwtString));

		return env;
	}

	protected invalidateSignatureString(environmentKey: string, jwtString: string): string {
		try {
			// SignedJWT.parse(jwtString)
			const parsedJwt = JWTUtil.parseJWT(jwtString);
			if (parsedJwt.type !== "signed") {
				throw new ParseException("Not a JWS header");
			}

			const signature = parsedJwt.signature as string;

			const bytes = Buffer.from(signature, "base64url");

			//Flip some of the bits in the signature to make it invalid
			for (let i = 0; i < bytes.length; i++) {
				bytes[i] ^= 0x5a;
			}

			const invalidSignature = bytes.toString("base64url");

			//Rebuild the JWT using Base64URL
			const parsedJwtParsedParts = parsedJwt.parts;

			return parsedJwtParsedParts[0] + "." + parsedJwtParsedParts[1] + "." + invalidSignature;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Couldn't parse JWT", e, args(environmentKey, jwtString));
			}
			throw e;
		}
	}
}
