/**
 * Request objects (OIDCC-6): the authorization request as an unsigned JWT, passed by value (`request`) or by
 * reference (`request_uri`, served by the suite's own server).
 *
 *   const request = authz.createAuthorizationRequest(op, client.client);
 *   const claims = requestObject.convertAuthorizationEndpointRequestToRequestObject(request.params);
 *   const jwt = requestObject.serializeRequestObjectWithNullAlgorithm(claims);
 *   const url = requestObject.buildRequestObjectByValueRedirectToAuthorizationEndpoint(op, request.params, claims, jwt);
 */
import { createHash } from "node:crypto";
import { condition, type Condition } from "../suite/conditions.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import { toUriString } from "../util/UriComponentsBuilder.ts";
import { JWTUtil, ParseException } from "../util/JWTUtil.ts";
import type { Op } from "./op.ts";

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
		const claimSet: Record<string, unknown> = JWTUtil.jwtClaimsSetAsJsonObject({
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
 * OIDCC-6.1) or differ from it, sorted by name.
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
		if (
			requiredDuplicates.includes(key) ||
			requestObjectValue == null ||
			requestParameterValue !== requestObjectValue
		) {
			query.set(key, requestParameterValue);
		}
	}
	const sorted = [...query.entries()].toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
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

/** upstream: condition/client/BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint.java */
export function buildRequestObjectByReferenceRedirectToAuthorizationEndpoint(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	requestObjectClaims: Record<string, unknown>,
	requestUri: RequestUri,
): string {
	const c: Condition = condition("BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint");
	return buildRedirect(c, op, params, requestObjectClaims, "request_uri", requestUri.fullUrl);
}

function isPrimitive(v: unknown): boolean {
	return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}
