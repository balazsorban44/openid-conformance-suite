import {
	AbstractCondition,
	args,
	isJsonNull,
	isJsonObject,
	jsonArrayContains,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class CheckRequestClaimsParameterMemberValues extends AbstractCondition {
	// https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
	private static readonly expectedRequestObjectClaimsParams: string[] = ["userinfo", "id_token"];

	// https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
	private static readonly validValuekeys: string[] = ["essential", "value", "values"];

	// Locations of expected claims to validate.
	private static readonly validClaimPaths: string[] = [
		"userinfo",
		"userinfo.verified_claims.verification",
		"userinfo.verified_claims.claims",
		"id_token",
		"id_token.verified_claims.verification",
		"id_token.verified_claims.claims",
	];

	// Add a claim to the list for the specified claims object.
	//
	// Parameters:
	//   claimsObject:     The claims object to be updated.
	//   claimsObjectPath: The path of the claims object (terminated with the claim name. eg. ["id_token", "name"]
	private addClaimMemberToClaimsObject(claimsObject: JsonObject, claimsObjectPath: string[]): void {
		const localClaimsObjectPath = [...claimsObjectPath];

		// Extract the claim name from the path.
		const claim = localClaimsObjectPath.pop() as string;
		// Construct the claims object name from the remaining path.
		// eg. "id_token.verified_claims.verification"
		const claimsObjectPathStr = localClaimsObjectPath.join(".");

		// Ensure the list of claims to be updated exists.
		if (!Object.prototype.hasOwnProperty.call(claimsObject, claimsObjectPathStr)) {
			claimsObject[claimsObjectPathStr] = [];
		}

		const claimsArray = claimsObject[claimsObjectPathStr] as JsonArray;
		if (!jsonArrayContains(claimsArray, claim)) {
			(claimsObject[claimsObjectPathStr] as JsonArray).push(claim);
		}
	}

	// Recurse through nested claims objects to identify and validate individual claims.
	//
	// Parameters:
	//   claimsObject:	  The claims object to be checked.
	//   claimsObjectPath:    The path of the claims object. eg. ["id_token", "verified_claims"]
	//   allMemberClaims:     A store for all identified claims.
	//   invalidMemberClaims: A store for invalid claims.
	private checkClaimsObject(
		claimsObject: JsonObject,
		claimsObjectPath: string[],
		allMemberClaims: JsonObject,
		invalidMemberClaims: JsonObject,
	): void {
		// In the case where the claim value is an empty object eg. 'id_token.iss : {}' no validation need
		// be performed, but the claim name needs to be added to the claim object path so the claim is
		// logged correctly as 'id_token.iss'.
		if (Object.keys(claimsObject).length === 0) {
			const localClaimsObjectPath = [...claimsObjectPath];
			this.addClaimMemberToClaimsObject(allMemberClaims, localClaimsObjectPath);
			return;
		}

		// Process all claims in the claims object.
		for (const key of Object.keys(claimsObject)) {
			const localClaimsObjectPath = [...claimsObjectPath];

			// Recurse down though nested claims objects.
			const value = claimsObject[key];
			if (isJsonObject(value)) {
				// Add the claim name to the claim object path.
				localClaimsObjectPath.push(key);

				this.checkClaimsObject(value, localClaimsObjectPath, allMemberClaims, invalidMemberClaims);
				continue;
			}

			// At this point we expect to be iterating through a claims object containing a set of claims
			// with non object values eg. '"essential" : true'. In this case we validate the claim name, but log
			// the parent object which is currently contained in the claimsObjectPath.
			//
			// So. for 'id_token.iss : { "essential" : true }' the claim is logged as "id_token.iss" with the
			// "essential" being validated.

			// In the case where the claim value is a null object eg. 'id_token.iss : null' no validation need
			// be performed, but the claim name needs to be added to the claim object path so the claim is
			// logged correctly as 'id_token.iss'.
			if (isJsonNull(value)) {
				// Add the claim name to the claims object path and log it's presence.
				localClaimsObjectPath.push(key);
				this.addClaimMemberToClaimsObject(allMemberClaims, localClaimsObjectPath);
				continue;
			}

			// In the case where the claim in an expected location does not contain the expected object or null eg.
			// 'id_token.iss : "12345678"'. Add the claim name to the claim object path so the claim is logged correctly as
			// 'id_token.iss'.
			for (const validPath of CheckRequestClaimsParameterMemberValues.validClaimPaths) {
				const path = localClaimsObjectPath.join(".");

				if (validPath.startsWith(path)) {
					localClaimsObjectPath.push(key);
				}
			}
			this.addClaimMemberToClaimsObject(allMemberClaims, localClaimsObjectPath);

			if (!CheckRequestClaimsParameterMemberValues.validValuekeys.includes(key)) {
				this.addClaimMemberToClaimsObject(invalidMemberClaims, localClaimsObjectPath);
			}
		}
	}

	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };

	override evaluate(env: Environment): Environment {
		// UPSTREAM: Java calls getAsJsonObject() on a possibly missing element (NullPointerException) before the null check below
		const requestObjectClaimsParameter = env.getElementFromObject(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			"claims",
		) as JsonObject;

		if (requestObjectClaimsParameter == null || Object.keys(requestObjectClaimsParameter).length === 0) {
			this.logSuccess("authorization request 'claims' parameter does not exist or is empty");
			return env;
		}

		const allMemberClaims: JsonObject = {};
		const invalidMemberClaims: JsonObject = {};

		// Process the top level claims parameters.
		// eg. 'userinfo'
		for (const claim of Object.keys(requestObjectClaimsParameter)) {
			// Ignore unexpected claims parameters
			if (!CheckRequestClaimsParameterMemberValues.expectedRequestObjectClaimsParams.includes(claim)) {
				continue;
			}

			const claimsObjectPath = [claim];
			// UPSTREAM: Java getAsJsonObject() throws if the member is not a JSON object
			const topLevelClaimsObject = requestObjectClaimsParameter[claim];
			if (!isJsonObject(topLevelClaimsObject)) {
				throw new TypeError("Not a JSON Object: " + JSON.stringify(topLevelClaimsObject));
			}
			this.checkClaimsObject(topLevelClaimsObject, claimsObjectPath, allMemberClaims, invalidMemberClaims);
		}

		if (Object.keys(invalidMemberClaims).length === 0) {
			this.logSuccess(
				"the authorization request id_token/userinfo claims contain only claim members with valid values",
				args("claim_members", allMemberClaims),
			);
		} else {
			throw this.error(
				"the authorization request id_token/userinfo claims contain claim members with invalid values",
				args("claim_members", allMemberClaims, "invalid_claims", invalidMemberClaims),
			);
		}

		return env;
	}
}
