/**
 * The emulated OP's user and its userinfo endpoint: the bearer token checks upstream runs on the RP's userinfo
 * request and the response (the user's claims filtered by the granted scopes).
 */
import { block, condition, skipped, type Condition } from "../suite/conditions.ts";
import type { IncomingRequest } from "../suite/server.ts";
import type { EmulatedOp } from "./op.ts";

/** The claims the emulated user has (upstream OIDCCLoadUserInfo.SUPPORTED_CLAIMS) */
export const SUPPORTED_CLAIMS: readonly string[] = [
	"sub",
	"name",
	"given_name",
	"family_name",
	"middle_name",
	"nickname",
	"preferred_username",
	"gender",
	"birthdate",
	"address",
	"zoneinfo",
	"locale",
	"phone_number",
	"phone_number_verified",
	"email",
	"email_verified",
	"website",
	"profile",
	"updated_at",
	"txn",
];

export type UserInfo = Record<string, unknown>;

const USER: UserInfo = {
	sub: "user-subject-1234531",
	name: "Demo T. User",
	given_name: "Demo",
	family_name: "User",
	middle_name: "Theresa",
	nickname: "Dee",
	preferred_username: "d.tu",
	gender: "female",
	birthdate: "2000-02-03",
	address: {
		street_address: "100 Universal City Plaza",
		locality: "Hollywood",
		region: "CA",
		postal_code: "91608",
		country: "USA",
	},
	zoneinfo: "America/Los_Angeles",
	locale: "en-US",
	phone_number: "+1 555 5550000",
	phone_number_verified: false,
	email: "user@example.com",
	email_verified: false,
	website: "https://openid.net/",
	profile: "https://example.com/user",
	updated_at: 1580000000,
	txn: "2c6fb585-d51b-465a-9dca-b8cd22a11451",
};

/** The emulated user's values for `claims` (upstream OIDCCLoadUserInfo.getUserInfoClaimsValues) */
export function userInfoClaimsValues(claims: readonly string[] = SUPPORTED_CLAIMS): UserInfo {
	const user: UserInfo = {};
	for (const claim of claims) {
		if (claim in USER) {
			user[claim] = structuredClone(USER[claim]);
		}
	}
	return user;
}

/** upstream: condition/rs/OIDCCLoadUserInfo.java */
export function oidccLoadUserInfo(): UserInfo {
	const user = userInfoClaimsValues();
	condition("OIDCCLoadUserInfo").success("Added user information", { user_info: user });
	return user;
}

const SCOPES_TO_CLAIMS: Record<string, string[]> = {
	openid: ["sub"],
	profile: [
		"name",
		"preferred_username",
		"given_name",
		"family_name",
		"middle_name",
		"nickname",
		"profile",
		"picture",
		"website",
		"gender",
		"zoneinfo",
		"locale",
		"updated_at",
		"birthdate",
	],
	email: ["email", "email_verified"],
	phone: ["phone_number", "phone_number_verified"],
	address: ["address"],
};

/**
 * The user's claims the granted scopes cover (upstream env "user_info_endpoint_response").
 *
 * upstream: condition/as/FilterUserInfoForScopes.java
 */
export function filterUserInfoForScopes(userInfo: UserInfo, scope: string, ...requirements: string[]): UserInfo {
	const out: UserInfo = {};
	for (const s of scope.split(" ")) {
		for (const claim of SCOPES_TO_CLAIMS[s] ?? []) {
			if (claim in userInfo) {
				out[claim] = userInfo[claim];
			}
		}
	}
	condition("FilterUserInfoForScopes", ...requirements).success("User info endpoint output", out);
	return out;
}

/** upstream: condition/as/ChangeSubInUserInfoResponseToBeInvalid.java */
export function changeSubInUserInfoResponseToBeInvalid(response: UserInfo, ...requirements: string[]): void {
	if (typeof response["sub"] !== "string") {
		// UPSTREAM: OIDFJSON.getString throws on a missing / non-string sub
		throw new Error("getString called on something that is not a string: " + JSON.stringify(response["sub"]));
	}
	response["sub"] = response["sub"] + "invalid";
	condition("ChangeSubInUserInfoResponseToBeInvalid", ...requirements).log(
		"Added invalid sub to userinfo endpoint output",
		response,
	);
}

/**
 * The access token the RP sent: the Authorization header (Bearer) or a form body parameter, never the query.
 *
 * upstream: condition/rs/OIDCCExtractBearerAccessTokenFromRequest.java
 */
export function oidccExtractBearerAccessTokenFromRequest(req: IncomingRequest, ...requirements: string[]): string {
	const c: Condition = condition("OIDCCExtractBearerAccessTokenFromRequest", ...requirements);
	let tokenFromHeader: string | null = null;
	let tokenFromParams: string | null = null;
	const authHeader = req.headers["authorization"];
	if (typeof authHeader === "string" && authHeader.toLowerCase().startsWith("bearer ")) {
		tokenFromHeader = authHeader.substring("bearer ".length);
	}
	const fromForm = req.body_form_params?.["access_token"];
	const fromQuery = req.query_string_params["access_token"];
	if (fromQuery != null) {
		c.failure("Request contains access_token parameter in query string", { access_token_query_parameter: fromQuery });
	}
	if (fromForm != null) {
		if (typeof fromForm === "string") {
			tokenFromParams = fromForm;
		} else {
			c.failure("Request body contains multiple access_token parameters", { access_token: fromForm });
		}
	}
	if (!tokenFromHeader && !tokenFromParams) {
		c.failure("Couldn't find a bearer token in request");
	}
	if (tokenFromHeader && tokenFromParams) {
		c.failure("Found more than one access token in request", {
			token_from_authorization_header: tokenFromHeader,
			token_from_request_parameters: tokenFromParams,
		});
	}
	const token = (tokenFromHeader || tokenFromParams) as string;
	c.success("Found access token on incoming request", { access_token: token });
	return token;
}

/** upstream: condition/rs/RequireBearerAccessToken.java */
export function requireBearerAccessToken(actual: string, expected: string | null, ...requirements: string[]): void {
	const c: Condition = condition("RequireBearerAccessToken", ...requirements);
	if (expected == null) {
		c.failure(
			"This endpoint must be called with an access token, but a suitable access token has not been created in this run of the test.",
		);
	}
	if (actual && actual === expected) {
		c.success("Found access token in request", { actual });
		return;
	}
	c.failure("Invalid access token ", { expected, actual });
}

/** upstream: condition/rs/ClearAccessTokenFromRequest.java */
export function clearAccessTokenFromRequest(): void {
	condition("ClearAccessTokenFromRequest").log("Removed incoming access token from environment");
}

/**
 * The userinfo request: a valid bearer token (header, form body or query, upstream supports all but rejects the
 * query), the response is the user's claims for the granted scopes, `customize` (the module's change, e.g.
 * ChangeSubInUserInfoResponseToBeInvalid) applied. Signed / encrypted userinfo responses are not supported yet.
 *
 * upstream: AbstractOIDCCClientTest.handleUserinfoEndpointRequest (validateUserinfoRequest, prepareUserinfoResponse,
 * signUserInfoResponseIfNecessary, encryptUserInfoResponseIfNecessary)
 */
export async function handleUserinfoRequest(
	op: EmulatedOp,
	req: IncomingRequest,
	customize?: (response: UserInfo) => void,
): Promise<{ response: Response; userinfo: UserInfo }> {
	return block("Userinfo endpoint", () => {
		const token = oidccExtractBearerAccessTokenFromRequest(req, "RFC6750-2", "OIDCC-5.3.1");
		requireBearerAccessToken(token, op.tokens?.accessToken ?? null, "OIDCC-5.3.1");
		const userinfo = filterUserInfoForScopes(op.userInfo, op.authorization?.scope ?? "", "OIDCC-5.4");
		customize?.(userinfo);
		clearAccessTokenFromRequest();
		const client: Record<string, unknown> = op.client ?? {};
		if (client["userinfo_signed_response_alg"] == null) {
			// If signed, the UserInfo Response SHOULD contain the Claims iss (issuer) and aud (audience) as members.
			skipped("AddIssAndAudToUserInfoResponse", { element: ["client", "userinfo_signed_response_alg"] }, "OIDCC-5.3.2");
			skipped("SignUserInfoResponse", { element: ["client", "userinfo_signed_response_alg"] }, "OIDCC-5.3.2");
		} else {
			throw new Error("TODO(port): signed userinfo responses (AddIssAndAudToUserInfoResponse, SignUserInfoResponse)");
		}
		if (client["userinfo_encrypted_response_alg"] == null) {
			skipped("EncryptUserInfoResponse", { element: ["client", "userinfo_encrypted_response_alg"] }, "OIDCC-5.3.2");
		} else {
			throw new Error("TODO(port): encrypted userinfo responses (EncryptUserInfoResponse)");
		}
		return { response: Response.json(userinfo), userinfo };
	});
}
