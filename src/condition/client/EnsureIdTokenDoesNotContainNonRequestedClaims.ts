import {
	args,
	deepCopy,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractVerifyScopesReturnedInClaims } from "./AbstractVerifyScopesReturnedInClaims.ts";

export class EnsureIdTokenDoesNotContainNonRequestedClaims extends AbstractVerifyScopesReturnedInClaims {
	// This is a list of claims that might be expected to appear in an id_token even if they were not explicitly requested
	// UPSTREAM: this static list is mutated in evaluate() below, so scope claims accumulate across conditions/tests
	static idTokenValidClaims: string[] = [
		// as per https://openid.net/specs/openid-connect-core-1_0.html#IDToken
		"iss",
		"sub",
		"aud",
		"exp",
		"iat",
		"auth_time",
		"nonce",
		"acr",
		"amr",
		"azp",
		// https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		"at_hash",
		"c_hash",
		// as per https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
		"nbf",
		"jti",
		// as per https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
		"sid",
		// as per https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
		"at_hash",
		// as per https://openid.net/specs/openid-financial-api-part-2-1_0.html#id-token-as-detached-signature
		"s_hash",
		// As per https://openbanking.atlassian.net/wiki/spaces/DZ/pages/83919096/Open+Banking+Security+Profile+-+Implementer+s+Draft+v1.1.2#OpenBankingSecurityProfile-Implementer'sDraftv1.1.2-HybridGrantParameters
		"openbanking_intent_id",
		// txn must be returned according to https://cdn.connectid.com.au/specifications/digitalid-identity-assurance-profile-06.html
		"txn",
	];

	static override pre: EnvironmentRequirements = { required: ["id_token", "authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		// For OpenID Connect, scopes can be used to request that specific sets of information be made available
		// as claim values.
		//
		// Here we map the scopes included in the authorization request to a set of claims and add them to the
		// valid claims list.
		const scopeStr = env.getString("authorization_endpoint_request", "scope");
		if (scopeStr) {
			const scopeList = scopeStr.split(" ");
			if (scopeList.includes("openid")) {
				for (const scope of scopeList) {
					const claimsList = this.SCOPE_STANDARD_CLAIMS.get(scope);
					if (claimsList == null) {
						continue;
					}
					for (const claim of claimsList) {
						if (!EnsureIdTokenDoesNotContainNonRequestedClaims.idTokenValidClaims.includes(claim)) {
							EnsureIdTokenDoesNotContainNonRequestedClaims.idTokenValidClaims.push(claim);
						}
					}
				}
			}
		}

		const idTokenClaims = deepCopy(env.getElementFromObject("id_token", "claims") as JsonObject);

		let failure = false;
		for (const key of Object.keys(idTokenClaims)) {
			if (EnsureIdTokenDoesNotContainNonRequestedClaims.idTokenValidClaims.includes(key)) {
				continue;
			}
			failure = true;
			this.logFailure("id_token contains non-requested claim '" + key + "'");
		}

		if (failure) {
			throw this.error(
				"id_token contains non-requested claims. This may indicate the authorization server is returning data about the user that it should not, or that a specification has been wrongly implemented, or that it implements an extension the conformance suite is currently aware of.",
				args("requested_scope", scopeStr, "supplied", idTokenClaims),
			);
		}

		this.logSuccess("no non-requested id_token claims found");

		return env;
	}
}
