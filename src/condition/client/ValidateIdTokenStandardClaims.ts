import { deepCopy, type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractValidateOpenIdStandardClaims } from "./AbstractValidateOpenIdStandardClaims.ts";

export class ValidateIdTokenStandardClaims extends AbstractValidateOpenIdStandardClaims {
	static idTokenNonIdentityClaims: string[] = [
		// as per https://openid.net/specs/openid-connect-core-1_0.html#IDToken
		"iss",
		// "sub" - leave sub in, it's present in userinfo too
		"aud",
		"exp",
		"iat",
		"auth_time",
		"nonce",
		"acr",
		"amr",
		"azp",
		// as per https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		"c_hash",
		"at_hash",
		// from FAPI standard
		"s_hash",
		// standard jwt claims https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
		"jti",
		"nbf",
		// as per https://openid.net/specs/openid-connect-4-identity-assurance-1_0-ID3.html#name-verified_claims-element
		"verified_claims",
	];

	static getIdTokenIdentityClaims(env: Environment): JsonObject {
		const idTokenClaims = deepCopy(env.getElementFromObject("id_token", "claims") as JsonObject);
		for (const e of ValidateIdTokenStandardClaims.idTokenNonIdentityClaims) {
			// remove the claims that are specific to the id_token, so we're left with just claims from
			// https://openid.net/specs/openid-connect-core-1_0.html#Claims
			// (these id_token claims are mostly checked in other conditions, ValidateIdToken
			// and the various validations of the hashes)
			delete idTokenClaims[e];
		}
		return idTokenClaims;
	}

	static override pre: EnvironmentRequirements = { required: ["id_token"] };
	static override post: EnvironmentRequirements = { required: ["id_token_unknown_claims"] };

	override evaluate(env: Environment): Environment {
		const idTokenClaims = ValidateIdTokenStandardClaims.getIdTokenIdentityClaims(env);

		const result = this.createObjectValidator(null, this.STANDARD_CLAIMS).isValid(idTokenClaims);

		env.putObject("id_token_unknown_claims", this.unknownClaims);

		if (result) {
			this.logSuccess("id_token claims are valid");
		} else {
			throw this.error("id_token claims are not valid", idTokenClaims);
		}

		return env;
	}
}
