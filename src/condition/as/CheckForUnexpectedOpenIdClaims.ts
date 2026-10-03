import {
	args,
	isJsonObject,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { AbstractValidateOpenIdStandardClaims } from "../client/AbstractValidateOpenIdStandardClaims.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class CheckForUnexpectedOpenIdClaims extends AbstractValidateOpenIdStandardClaims {
	private standardClaimsAdditions: string[] = [
		// As per https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.5.1.1
		"acr",
		// As per https://openbanking-brasil.github.io/specs-seguranca/open-banking-brasil-financial-api-1_ID3.html#section-7.2.2-8
		// note that cpf & cnpj have been removed from the latest Brazil standard that starts in ~Apr 2024, so we can remove them once we stop issues certifications for the older profile
		"cpf",
		// As per https://openbanking-brasil.github.io/specs-seguranca/open-banking-brasil-financial-api-1_ID3.html#section-7.2.2-10
		"cnpj",
		// As per https://openbanking.atlassian.net/wiki/spaces/DZ/pages/83919096/Open+Banking+Security+Profile+-+Implementer+s+Draft+v1.1.2#OpenBankingSecurityProfile-Implementer'sDraftv1.1.2-HybridGrantParameters
		"openbanking_intent_id",
		// as per https://openid.net/specs/openid-connect-4-identity-assurance-1_0-ID3.html#name-verified_claims-element
		"verified_claims",
	];

	// For success/failure result purposes we maintain allMemberClaims/invalidMemberClaims maps
	//
	// eg. allMemberClaims:
	//       id_token
	//	   given_name
	//	   ...
	//       userinfo
	//	   family_name
	//	   ...
	private addClaimMemberToMap(claim: string, claimMember: string, map: Map<string, string[]>): void {
		let claimsList: string[];

		if (map.has(claim)) {
			claimsList = map.get(claim) as string[];
		} else {
			claimsList = [];
		}

		claimsList.push(claimMember);
		map.set(claim, claimsList);
	}

	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		const allMemberClaims = new Map<string, string[]>();
		const unknownMemberClaims = new Map<string, string[]>();

		// UPSTREAM: Java calls getAsJsonObject() on a possibly missing element (NullPointerException) so the null check below is
		// effectively dead code upstream
		const claimsParameter = env.getElementFromObject(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
		) as JsonObject | undefined;

		if (claimsParameter == null || Object.keys(claimsParameter).length === 0) {
			this.logSuccess("authorization request 'claims' parameter does not exist or is empty");
			return env;
		}

		for (const claim of Object.keys(claimsParameter)) {
			const claimObject = claimsParameter[claim];

			if (isJsonObject(claimObject)) {
				for (const member of Object.keys(claimObject)) {
					this.addClaimMemberToMap(claim, member, allMemberClaims);

					if (this.STANDARD_CLAIMS.has(member) || this.standardClaimsAdditions.includes(member)) {
						continue;
					}

					this.addClaimMemberToMap(claim, member, unknownMemberClaims);
				}
			}
		}

		if (unknownMemberClaims.size === 0) {
			this.logSuccess(
				"authorization request 'claims' parameter member objects contain only expected claims",
				args("claims", allMemberClaims),
			);
		} else {
			throw this.error(
				"unknown claims found in authorization request 'claims' parameter member objects",
				args("claims", allMemberClaims, "unknown_claims", unknownMemberClaims),
			);
		}

		return env;
	}
}
