/**
 * Request objects (OIDCC-6): the authorization request as a JWT (unsigned, or signed with the client's key), passed by
 * value (`request`) or by reference (`request_uri`, served by the suite's own server).
 *
 *   const request = authz.createAuthorizationRequest(op, client.client);
 *   const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(request.params);
 *   const jwt = requestObject.serializeRequestObjectWithNullAlgorithm(claims);
 *   const url = requestObject.buildRequestObjectByValueRedirectToAuthorizationEndpoint(op, request.params, claims, jwt);
 */
import { createHash } from "node:crypto";
import { condition, type Condition } from "../suite/conditions.ts";
import { getSigningKey, signJwt } from "../suite/jose.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import { toUriString } from "../suite/uri.ts";
import { jwtClaimsSetAsJsonObject } from "../suite/jose-jwt.ts";
import { ParseException } from "../suite/errors.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { Op } from "./op.ts";
import type { Client, ClientKeys } from "./registration.ts";

/** A request_uri the suite serves: the path below the suite's base url and the full url (with its fragment) */
export interface RequestUri {
	path: string;
	fullUrl: string;
}

/** upstream: condition/client/ConvertAuthorizationEndpointRequestToRequestObject.java */
export function convertAuthorizationEndpointRequestToRequestObject(
	params: Record<string, unknown>,
): Record<string, unknown> {
	const claims = structuredClone(params);
	condition("ConvertAuthorizationEndpointRequestToRequestObject").success("Created request object claims", {
		request_object_claims: claims,
	});
	return claims;
}

/**
 * The claims as an unsecured JWT ({"alg":"none"}, empty signature).
 *
 * upstream: condition/client/SerializeRequestObjectWithNullAlgorithm.java (AbstractSignClaimsWithNullAlgorithm)
 */
export function serializeRequestObjectWithNullAlgorithm(requestObjectClaims: Record<string, unknown>): string {
	const c: Condition = condition("SerializeRequestObjectWithNullAlgorithm");
	try {
		// JWTClaimsSet.parse(objectClaims.toString()) followed by claimSet.toJSONObject()
		const claimSet: Record<string, unknown> = jwtClaimsSetAsJsonObject({
			type: "plain",
			serialized: "",
			parts: [],
			header: {},
			payload: JSON.stringify(requestObjectClaims),
			signature: null,
		});
		// toJSONObject() (as opposed to toJSONObject(true)) omits claims with null values
		for (const name of Object.keys(claimSet)) {
			if (claimSet[name] === null) {
				delete claimSet[name];
			}
		}
		// new PlainHeader()
		const header = { alg: "none" };
		// new PlainJWT(header, claimSet).serialize(): the unsecured JWT has an empty third part
		const serialized =
			Buffer.from(JSON.stringify(header)).toString("base64url") +
			"." +
			Buffer.from(JSON.stringify(claimSet)).toString("base64url") +
			".";
		c.success("Serialized the request object", { header, claims: claimSet, request_object_serialized: serialized });
		return serialized;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom(e.message, e);
		}
		throw e;
	}
}

/** upstream: condition/client/AddAudToRequestObject.java */
export function addAudToRequestObject(
	claims: Record<string, unknown>,
	metadata: Pick<ServerMetadata, "issuer">,
	...requirements: string[]
): void {
	const c: Condition = condition("AddAudToRequestObject", ...requirements);
	if (metadata.issuer != null) {
		claims["aud"] = metadata.issuer;
		c.success("Added aud to request object claims", { aud: metadata.issuer });
	} else {
		// Only a "should" requirement
		c.log("Request object contains no audience and server issuer URL not found");
	}
}

/** upstream: condition/client/AddIssToRequestObject.java */
export function addIssToRequestObject(
	claims: Record<string, unknown>,
	client: Pick<Client, "client_id">,
	...requirements: string[]
): void {
	const c: Condition = condition("AddIssToRequestObject", ...requirements);
	if (client.client_id != null) {
		claims["iss"] = client.client_id;
		c.success("Added iss to request object claims", { iss: client.client_id });
	} else {
		// Only a "should" requirement
		c.log("Request object contains no issuer and client ID not found");
	}
}

/**
 * The claims signed with the client's (single) signing key.
 *
 * upstream: condition/client/SignRequestObject.java (AbstractSignJWT)
 */
export async function signRequestObject(
	claims: Record<string, unknown>,
	client: { keys: ClientKeys | null },
	...requirements: string[]
): Promise<string> {
	const c: Condition = condition("SignRequestObject", ...requirements);
	if (client.keys == null) {
		c.failure("Couldn't find jwks");
	}
	const { jws, verifiable } = await signJwt(c, claims, client.keys.jwks);
	const [header] = jws.split(".");
	c.success("Signed the request object", {
		request_object: verifiable,
		header: JSON.parse(Buffer.from(header, "base64url").toString()),
		claims,
	});
	return jws;
}

/**
 * A random url below the suite's base url for the OP to fetch the request object from, with the base64url SHA-256 of
 * a random value as fragment (OIDCC-6.2; not in JAR).
 *
 * upstream: condition/common/CreateRandomRequestUriWithFragment.java
 */
export function createRandomRequestUriWithFragment(baseUrl: string, ...requirements: string[]): RequestUri {
	const c: Condition = condition("CreateRandomRequestUriWithFragment", ...requirements);
	if (baseUrl === "") {
		c.failure("Base URL is empty");
	}
	// spec requires full url to be no more than 512 characters; "the request_uri MUST have appropriate entropy for
	// its lifetime" (64 characters, as the python suite's 8 characters are ~48 bits of entropy)
	const path = "requesturi/" + randomAlphanumeric(64);
	// the actual content of the request object is not used as it is not available prior to client registration
	const fragment = createHash("sha256")
		.update(Buffer.from(randomAlphanumeric(64), "ascii"))
		.digest()
		.toString("base64url");
	const requestUri = { path, fullUrl: baseUrl + "/" + path + "#" + fragment };
	c.log("Created random URL for request_uri", { request_uri: requestUri });
	return requestUri;
}

/**
 * The URL to send the browser to: `paramName` (request / request_uri) plus the parameters that must also be sent
 * with OAuth 2.0 syntax even when they are in the request object (response_type, client_id, scope, redirect_uri;
 * OIDCC-6.1) or differ from it, sorted by name. Without `includeDuplicates` (JAR / PAR allow leaving them out) only
 * client_id is added; `reverseParameterOrder` sorts the query in reverse to test that the OP handles other orders.
 *
 * upstream: condition/client/AbstractBuildRequestObjectRedirectToAuthorizationEndpoint.java
 */
function buildRedirect(
	c: Condition,
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	requestObjectClaims: Record<string, unknown>,
	paramName: string,
	paramValue: string,
	includeDuplicates = true,
	reverseParameterOrder = false,
): string {
	const requiredDuplicates = ["response_type", "client_id", "scope", "redirect_uri"];
	const authorizationEndpoint = op.metadata.authorization_endpoint;
	if (!authorizationEndpoint) {
		c.failure("Couldn't find authorization endpoint");
	}
	const query = new Map<string, string>();
	query.set(paramName, paramValue);
	for (const key of Object.keys(params)) {
		const inObject = requestObjectClaims[key];
		const inRequest = params[key];
		if ((inObject !== undefined && !isPrimitive(inObject)) || !isPrimitive(inRequest)) {
			// only handle stringable values for now (as BuildPlainRedirectToAuthorizationEndpoint)
			continue;
		}
		const requestObjectValue = inObject === undefined ? null : String(inObject);
		const requestParameterValue = String(inRequest);
		if (includeDuplicates) {
			if (
				requiredDuplicates.includes(key) ||
				requestObjectValue == null ||
				requestParameterValue !== requestObjectValue
			) {
				query.set(key, requestParameterValue);
			}
		} else if (key === "client_id") {
			query.set(key, requestParameterValue);
		}
	}
	const order = reverseParameterOrder ? -1 : 1;
	const sorted = [...query.entries()].toSorted(([a], [b]) => (a < b ? -order : a > b ? order : 0));
	const redirectTo = toUriString(authorizationEndpoint, sorted);
	c.success("Sending to authorization endpoint", { redirect_to_authorization_endpoint: redirectTo });
	return redirectTo;
}

/** upstream: condition/client/BuildRequestObjectByValueRedirectToAuthorizationEndpoint.java */
export function buildRequestObjectByValueRedirectToAuthorizationEndpoint(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	requestObjectClaims: Record<string, unknown>,
	requestObject: string,
): string {
	const c: Condition = condition("BuildRequestObjectByValueRedirectToAuthorizationEndpoint");
	return buildRedirect(c, op, params, requestObjectClaims, "request", requestObject);
}

/**
 * upstream: condition/client/BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint.java (`requestUri`: the
 * suite's own request_uri, or the one a PAR endpoint returned)
 */
export function buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	requestObjectClaims: Record<string, unknown>,
	requestUri: RequestUri | string,
	...requirements: string[]
): string {
	const c: Condition = condition("BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint", ...requirements);
	const value = typeof requestUri === "string" ? requestUri : requestUri.fullUrl;
	return buildRedirect(c, op, params, requestObjectClaims, "request_uri", value);
}

/** upstream: condition/client/BuildRequestObjectByReferenceRedirectToAuthorizationEndpointReorderedParams.java */
export function buildRequestObjectByReferenceRedirectToAuthorizationEndpointReorderedParams(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	requestObjectClaims: Record<string, unknown>,
	requestUri: string,
	...requirements: string[]
): string {
	const c: Condition = condition(
		"BuildRequestObjectByReferenceRedirectToAuthorizationEndpointReorderedParams",
		...requirements,
	);
	return buildRedirect(c, op, params, requestObjectClaims, "request_uri", requestUri, true, true);
}

/** upstream: condition/client/BuildRequestObjectByReferenceRedirectToAuthorizationEndpointWithoutDuplicates.java */
export function buildRequestObjectByReferenceRedirectToAuthorizationEndpointWithoutDuplicates(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	requestObjectClaims: Record<string, unknown>,
	requestUri: string,
	...requirements: string[]
): string {
	const c: Condition = condition(
		"BuildRequestObjectByReferenceRedirectToAuthorizationEndpointWithoutDuplicates",
		...requirements,
	);
	return buildRedirect(c, op, params, requestObjectClaims, "request_uri", requestUri, false, false);
}

function isPrimitive(v: unknown): boolean {
	return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

/** upstream: condition/client/AddIatToRequestObject.java */
export function addIatToRequestObject(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["iat"] = Math.floor(Date.now() / 1000);
	condition("AddIatToRequestObject", ...requirements).success("Added iat to request object claims", {
		iat: claims["iat"],
	});
}

/** upstream: condition/client/AddNbfToRequestObject.java */
export function addNbfToRequestObject(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["nbf"] = Math.floor(Date.now() / 1000);
	condition("AddNbfToRequestObject", ...requirements).success("Added nbf to request object claims", {
		nbf: claims["nbf"],
	});
}

/** upstream: condition/client/AddExpToRequestObject.java */
export function addExpToRequestObject(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["exp"] = Math.floor(Date.now() / 1000) + 5 * 60;
	condition("AddExpToRequestObject", ...requirements).success("Added exp to request object claims", {
		exp: claims["exp"],
	});
}

/** upstream: condition/client/AddExpiredExpToRequestObject.java */
export function addExpiredExpToRequestObject(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["exp"] = Math.floor(Date.now() / 1000) - 3600;
	condition("AddExpiredExpToRequestObject", ...requirements).success("Added expired exp to request object claims", {
		exp: claims["exp"],
	});
}

/** upstream: condition/client/AddClientIdToRequestObject.java */
export function addClientIdToRequestObject(
	claims: Record<string, unknown>,
	client: Pick<Client, "client_id">,
	...requirements: string[]
): void {
	const c: Condition = condition("AddClientIdToRequestObject", ...requirements);
	const clientId = client.client_id;
	if (clientId == null) {
		c.failure("missing client_id in environment");
	}
	claims["client_id"] = clientId;
	c.success("Added client_id to request object claims", { client_id: clientId });
}

/** upstream: condition/client/AddMultipleAudToRequestObject.java */
export function addMultipleAudToRequestObject(
	claims: Record<string, unknown>,
	metadata: Pick<ServerMetadata, "issuer">,
	...requirements: string[]
): void {
	delete claims["aud"];
	const aud: string[] = [];
	if (metadata.issuer != null) {
		aud.push(metadata.issuer);
	}
	aud.push("https://other1.example.com", "invalid");
	claims["aud"] = aud;
	condition("AddMultipleAudToRequestObject", ...requirements).success("Added multiple aud to request object claims", {
		aud,
	});
}

/**
 * SignRequestObject with a `typ` header of "oauth-authz-req+jwt" in randomised case (JAR-4: the media type is case
 * insensitive).
 *
 * upstream: condition/client/SignRequestObjectIncludeMediaType.java (AbstractSignJWT)
 */
export async function signRequestObjectIncludeMediaType(
	claims: Record<string, unknown>,
	client: { keys: ClientKeys | null },
	...requirements: string[]
): Promise<string> {
	const c: Condition = condition("SignRequestObjectIncludeMediaType", ...requirements);
	if (client.keys == null) {
		c.failure("Couldn't find jwks");
	}
	const { jws, verifiable } = await signJwt(c, claims, client.keys.jwks, { typ: "OautH-auThZ-REQ+jWt" });
	const [header] = jws.split(".");
	c.success("Signed the request object", {
		request_object: verifiable,
		header: JSON.parse(Buffer.from(header, "base64url").toString()),
		claims,
		key: getSigningKey(c, "signing", client.keys.jwks),
	});
	return jws;
}
