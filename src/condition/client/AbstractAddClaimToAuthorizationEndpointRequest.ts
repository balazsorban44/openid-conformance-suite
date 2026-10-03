import {
	AbstractCondition,
	args,
	isJsonObject,
	RandomStringUtils,
	type Environment,
	type JsonObject,
} from "../../framework/index.ts";

// We test (if we have enough supported claims!) all the ways a claim can be requested as per
// https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
// We don't test value / values as we don't know what values the server may return
const ClaimRequestType = ["AsNull", "AsEmpty", "EssentialTrue", "Random", "EssentialFalse"] as const;
type ClaimRequestType = (typeof ClaimRequestType)[number];

function nextClaimRequestType(requestType: ClaimRequestType): ClaimRequestType {
	return ClaimRequestType[(ClaimRequestType.indexOf(requestType) + 1) % ClaimRequestType.length];
}

/** Java: enum LocationToRequestClaim { ID_TOKEN, USERINFO } */
export const LocationToRequestClaim = {
	ID_TOKEN: "ID_TOKEN",
	USERINFO: "USERINFO",
} as const;
export type LocationToRequestClaim = (typeof LocationToRequestClaim)[keyof typeof LocationToRequestClaim];

export abstract class AbstractAddClaimToAuthorizationEndpointRequest extends AbstractCondition {
	/**
	 * Add claims to given claims object, using different forms of request
	 * @param claimsObject Claims object - i.e. id_token or userinfo entry inside 'claims' in request
	 * @param claimsToAdd Names of the claims to request
	 */
	protected addRequestsForClaims(claimsObject: JsonObject, claimsToAdd: string[]): void {
		let requestType: ClaimRequestType = ClaimRequestType[0];
		for (const claimName of claimsToAdd) {
			if (requestType === "AsNull") {
				claimsObject[claimName] = null;
			} else {
				const claimBody: JsonObject = {};
				switch (requestType) {
					case "AsEmpty":
						break;
					case "EssentialTrue":
						claimBody["essential"] = true;
						break;
					case "Random":
						// "Other members MAY be defined to provide additional information about the requested Claims. Any members used that are not understood MUST be ignored."
						claimBody[RandomStringUtils.nextAlphanumeric(10)] = RandomStringUtils.nextAlphanumeric(10);
						break;
					case "EssentialFalse":
						claimBody["essential"] = false;
						break;
				}
				claimsObject[claimName] = claimBody;
			}
			requestType = nextClaimRequestType(requestType);
		}
	}

	addClaim(
		env: Environment,
		locationToRequestClaim: LocationToRequestClaim,
		claim: string,
		value: string | null,
		essential: boolean,
	): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;
		let locationStr: string;
		switch (locationToRequestClaim) {
			case "ID_TOKEN":
				locationStr = "id_token";
				break;
			case "USERINFO":
				locationStr = "userinfo";
				break;
			default:
				throw this.error("Unknown locationToRequestClaim value, this is a bug in the test condition");
		}

		const claimsIdToken = this.getClaimsForLocation(authorizationEndpointRequest, locationStr);

		const claimBody: JsonObject = {};
		if (value != null) {
			claimBody["value"] = value;
		}
		claimBody["essential"] = essential;
		claimsIdToken[claim] = claimBody;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess(
			"Added " + claim + " claim to authorization_endpoint_request",
			args("authorization_endpoint_request", authorizationEndpointRequest),
		);

		return env;
	}

	protected getClaimsForLocation(authorizationEndpointRequest: JsonObject, locationStr: string): JsonObject {
		let claims: JsonObject;
		if ("claims" in authorizationEndpointRequest) {
			const claimsElement = authorizationEndpointRequest["claims"];
			if (isJsonObject(claimsElement)) {
				claims = claimsElement;
			} else {
				throw this.error(
					"Invalid claims entry in authorization_endpoint_request",
					args("authorization_endpoint_request", authorizationEndpointRequest),
				);
			}
		} else {
			claims = {};
			authorizationEndpointRequest["claims"] = claims;
		}

		let identityClaimsForRequestedLocation: JsonObject;
		if (locationStr in claims) {
			const idTokenElement = claims[locationStr];
			if (isJsonObject(idTokenElement)) {
				identityClaimsForRequestedLocation = idTokenElement;
			} else {
				throw this.error(
					"Invalid " + locationStr + " entry in authorization_endpoint_request",
					args("authorization_endpoint_request", authorizationEndpointRequest),
				);
			}
		} else {
			identityClaimsForRequestedLocation = {};
			claims[locationStr] = identityClaimsForRequestedLocation;
		}
		return identityClaimsForRequestedLocation;
	}
}
