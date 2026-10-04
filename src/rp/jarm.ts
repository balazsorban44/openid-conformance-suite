/**
 * JARM at the emulated authorization server (fapi_response_mode=jarm): the metadata that announces it, the
 * `response` JWT of the authorization response (iss, aud, code, state, exp, signed with the server's key), the
 * redirect that carries it, and the defects the negative RP tests put into it (iss / aud / exp missing or wrong, a
 * broken signature, alg none).
 *
 * upstream: AbstractFAPI2SPFinalClientTest.createJARMResponse and the condition/as/jarm conditions
 */
import { condition, skipped, type Condition } from "../suite/conditions.ts";
import { ParseException } from "../suite/errors.ts";
import { signJwt, type Jwks } from "../suite/jose.ts";
import { parseJWT } from "../suite/jose-jwt.ts";
import { toUriString } from "../suite/uri.ts";
import { addResponseTypeCodeToServerConfiguration, type ServerMetadata } from "./discovery.ts";
import { signClaimsWithNullAlgorithm } from "./id-token.ts";
import type { RpClient } from "./registration.ts";

/** upstream env "jarm_response_claims" */
export type JarmClaims = Record<string, unknown>;

// ---------------------------------------------------------------------------------------------------------------
// the server configuration

/** upstream: condition/as/AddJARMResponseModeToServerConfiguration.java */
export function addJARMResponseModeToServerConfiguration(server: ServerMetadata, ...requirements: string[]): void {
	const data = ["jwt"];
	server["response_modes_supported"] = data;
	condition("AddJARMResponseModeToServerConfiguration", ...requirements).success(
		"Added jwt as response_modes_supported",
		{ response_modes_supported: data },
	);
}

/** upstream: condition/as/AddAuthorizationSigningAlgValuesSupportedToServerConfiguration.java */
export function addAuthorizationSigningAlgValuesSupportedToServerConfiguration(
	server: ServerMetadata,
	signingAlg: string,
	...requirements: string[]
): void {
	const data = [signingAlg];
	server["authorization_signing_alg_values_supported"] = data;
	condition("AddAuthorizationSigningAlgValuesSupportedToServerConfiguration", ...requirements).success(
		"Added authorization_signing_alg_values_supported to server configuration",
		{ alg_values: data },
	);
}

/**
 * upstream: sequence/as/AddJARMToServerConfiguration.java with
 * condition/as/AddResponseTypeCodeToServerConfiguration.java, AddJARMResponseModeToServerConfiguration.java,
 * AddAuthorizationSigningAlgValuesSupportedToServerConfiguration.java
 */
export function addJARMToServerConfiguration(server: ServerMetadata, signingAlg: string): void {
	addResponseTypeCodeToServerConfiguration(server, "FAPI1-ADV-5.2.2-2");
	addJARMResponseModeToServerConfiguration(server, "FAPI1-ADV-5.2.2.2");
	addAuthorizationSigningAlgValuesSupportedToServerConfiguration(server, signingAlg, "JARM-4", "FAPI1-ADV-8.6");
}

// ---------------------------------------------------------------------------------------------------------------
// the response

/**
 * The claims of the JARM response: iss, aud (the client_id), code, state (when the request had one), exp in 10
 * minutes.
 *
 * upstream: condition/as/jarm/GenerateJARMResponseClaims.java
 */
export function generateJARMResponseClaims(
	issuer: string,
	code: string,
	clientId: string,
	state: string | null,
	...requirements: string[]
): JarmClaims {
	const claims: JarmClaims = { iss: issuer, aud: clientId, code };
	if (state) {
		claims["state"] = state;
	}
	// 10 minutes
	claims["exp"] = Math.floor(Date.now() / 1000) + 600;
	condition("GenerateJARMResponseClaims", ...requirements).log("Created JARM response claims", claims);
	return claims;
}

/**
 * Signs the JARM response claims with the server's single signing key.
 *
 * upstream: condition/as/jarm/SignJARMResponse.java (AbstractSignJWT.signJWT)
 */
export async function signJARMResponse(
	claims: JarmClaims,
	serverJwks: Jwks,
	...requirements: string[]
): Promise<string> {
	const c: Condition = condition("SignJARMResponse", ...requirements);
	const { jws, verifiable } = await signJwt(c, claims, serverJwks);
	c.success("Signed the JARM response", { jarm_response: verifiable });
	return jws;
}

/**
 * The JARM response is encrypted when the client registered authorization_encrypted_response_alg (not supported
 * yet; the FAPI 2 client tests' static clients do not).
 *
 * upstream: condition/as/EncryptJARMResponse.java
 */
export function encryptJARMResponse(jarmResponse: string, client: RpClient): string {
	if (client["authorization_encrypted_response_alg"] != null) {
		throw new Error("TODO(port): encrypted JARM responses (EncryptJARMResponse)");
	}
	return jarmResponse;
}

/**
 * EncryptJARMResponse when the client has an authorization_encrypted_response_alg, else the skip upstream logs.
 *
 * upstream: AbstractFAPI2SPFinalClientTest.encryptJARMResponse
 */
export function encryptJARMResponseIfConfigured(jarmResponse: string, client: RpClient): string {
	if (client["authorization_encrypted_response_alg"] == null) {
		skipped("EncryptJARMResponse", { element: ["client", "authorization_encrypted_response_alg"] }, "JARM-3");
		return jarmResponse;
	}
	return encryptJARMResponse(jarmResponse, client);
}

/**
 * The redirect to the client's redirect_uri with the JARM response as the `response` query parameter.
 * `responseParams`: the authorization response parameters (their redirect_uri is taken out, as upstream does).
 *
 * upstream: condition/as/jarm/SendJARMResponseWitResponseModeQuery.java
 */
export function sendJARMResponseWitResponseModeQuery(
	responseParams: Record<string, string>,
	jarmResponse: string,
	...requirements: string[]
): string {
	const redirectUri = responseParams["redirect_uri"];
	delete responseParams["redirect_uri"];
	if (typeof redirectUri !== "string") {
		// UPSTREAM: OIDFJSON.getString(null) throws a NullPointerException
		throw new TypeError("getString called on something that is not a string: null");
	}
	const redirectTo = toUriString(redirectUri, [["response", jarmResponse]]);
	condition("SendJARMResponseWitResponseModeQuery", ...requirements).log("Redirecting back to client", {
		uri: redirectTo,
	});
	return redirectTo;
}

// ---------------------------------------------------------------------------------------------------------------
// the defects of the negative tests

/** upstream: condition/as/RemoveIssFromJarm.java */
export function removeIssFromJarm(claims: JarmClaims, ...requirements: string[]): void {
	delete claims["iss"];
	condition("RemoveIssFromJarm", ...requirements).success("Removed iss value from JARM claims", {
		jarm_response_claims: claims,
	});
}

/** upstream: condition/as/AddInvalidIssValueToJarm.java */
export function addInvalidIssValueToJarm(claims: JarmClaims, ...requirements: string[]): void {
	const c: Condition = condition("AddInvalidIssValueToJarm", ...requirements);
	const iss = claims["iss"];
	// Add number 1 onto end of iss string
	if (iss == null) {
		c.failure("jarm_response_claims does not contain iss", { jarm_response_claims: claims });
	}
	const concat = String(iss) + 1;
	claims["iss"] = concat;
	c.success("Added invalid iss to JARM response claims", { jarm_response_claims: claims, iss: concat });
}

/** upstream: condition/as/RemoveAudFromJarm.java */
export function removeAudFromJarm(claims: JarmClaims, ...requirements: string[]): void {
	delete claims["aud"];
	condition("RemoveAudFromJarm", ...requirements).success("Removed aud value from JARM claims", {
		jarm_response_claims: claims,
	});
}

/** upstream: condition/as/AddInvalidAudValueToJarm.java */
export function addInvalidAudValueToJarm(claims: JarmClaims, ...requirements: string[]): void {
	const c: Condition = condition("AddInvalidAudValueToJarm", ...requirements);
	const aud = claims["aud"];
	// Add number 1 onto end of aud string
	if (aud == null) {
		c.failure("jarm_response_claims does not contain aud", { jarm_response_claims: claims });
	}
	const concat = String(aud) + 1;
	claims["aud"] = concat;
	c.success("Added invalid aud to JARM response claims", { jarm_response_claims: claims, aud: concat });
}

/** upstream: condition/as/RemoveExpFromJarm.java */
export function removeExpFromJarm(claims: JarmClaims, ...requirements: string[]): void {
	delete claims["exp"];
	condition("RemoveExpFromJarm", ...requirements).success("Removed exp value from JARM claims", {
		jarm_response_claims: claims,
	});
}

/** upstream: condition/as/AddInvalidExpiredExpValueToJarm.java */
export function addInvalidExpiredExpValueToJarm(claims: JarmClaims, ...requirements: string[]): void {
	const exp = Math.floor(Date.now() / 1000) - 60 * 6;
	claims["exp"] = exp;
	condition("AddInvalidExpiredExpValueToJarm", ...requirements).success("Added expired exp value to JARM claims", {
		jarm_response_claims: claims,
		exp: new Date(exp * 1000).toISOString(),
	});
}

/**
 * Flips bits of the signature so that it no longer verifies.
 *
 * upstream: condition/as/InvalidateJarmSignature.java (AbstractInvalidateJwsSignature)
 */
export function invalidateJarmSignature(jarmResponse: string, ...requirements: string[]): string {
	const c: Condition = condition("InvalidateJarmSignature", ...requirements);
	let invalid: string;
	try {
		const jwt = parseJWT(jarmResponse);
		if (jwt.type !== "signed") {
			throw new ParseException("Not a JWS header");
		}
		const bytes = Buffer.from(jwt.signature as string, "base64url");
		// Flip some of the bits in the signature to make it invalid
		for (let i = 0; i < bytes.length; i++) {
			bytes[i] ^= 0x5a;
		}
		invalid = jwt.parts[0] + "." + jwt.parts[1] + "." + bytes.toString("base64url");
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse JWT", e, { jarm_response: jarmResponse });
		}
		throw e;
	}
	c.log("Made the jarm_response signature invalid", { jarm_response: invalid });
	return invalid;
}

/** upstream: condition/as/SignJarmWithNullAlgorithm.java */
export function signJarmWithNullAlgorithm(claims: JarmClaims, ...requirements: string[]): string {
	return signClaimsWithNullAlgorithm(condition("SignJarmWithNullAlgorithm", ...requirements), claims, "jarm_response", {
		claimsNotFound: "JARM claims not found",
		success: "Signed the JARM response with null algorithm",
	});
}
