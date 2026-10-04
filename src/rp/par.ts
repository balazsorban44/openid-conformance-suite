/**
 * The emulated authorization server's pushed authorization request endpoint (RFC 9126): its metadata, the checks on
 * the pushed request (a request object, no request_uri, PKCE), the request_uri it answers with, and the checks on
 * the authorization request that then uses the request_uri (only client_id and request_uri, the pushed parameters
 * as the effective request).
 *
 * upstream: AbstractFAPI2SPFinalClientTest.parEndpoint, authorizationEndpoint (the PAR conditions)
 */
import { randomUUID } from "node:crypto";
import { condition, type Condition } from "../suite/conditions.ts";
import type { Jwks, ParsedJwt } from "../suite/jose.ts";
import type { IncomingRequest } from "../suite/server.ts";
import type { AuthorizationParams } from "./authorization.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { RpClient } from "./registration.ts";
import { processRequestObjectString } from "./request-object.ts";
import type { CodeChallenge } from "./token.ts";

/** A parameter read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function param(params: Record<string, unknown>, name: string): string | null {
	const v = params[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

// ---------------------------------------------------------------------------------------------------------------
// the server configuration

/**
 * The PAR endpoint is the token endpoint's url with `par` in place of `token` (and its mTLS alias likewise).
 *
 * upstream: condition/as/par/AddPushedAuthorizationRequestEndpointToServerConfig.java
 */
export function addPushedAuthorizationRequestEndpointToServerConfig(
	server: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition("AddPushedAuthorizationRequestEndpointToServerConfig", ...requirements);
	const tokenEndpoint = String(server.token_endpoint);
	const parEndpoint = tokenEndpoint.replace(/token$/, "par");
	let mtlsParEndpoint: string | null = null;
	const aliases = server["mtls_endpoint_aliases"];
	if (aliases != null && typeof aliases === "object" && !Array.isArray(aliases)) {
		const mtlsAliases = aliases as Record<string, unknown>;
		mtlsParEndpoint = String(mtlsAliases["token_endpoint"]).replace(/token$/, "par");
		mtlsAliases["pushed_authorization_request_endpoint"] = mtlsParEndpoint;
	}
	server["pushed_authorization_request_endpoint"] = parEndpoint;
	if (mtlsParEndpoint != null) {
		c.log("Added pushed_authorization_request_endpoint to server configuration", {
			endpoint: parEndpoint,
			mtls_endpoint: mtlsParEndpoint,
		});
	} else {
		c.log("Added pushed_authorization_request_endpoint to server configuration", { endpoint: parEndpoint });
	}
}

/** upstream: condition/as/par/AddRequirePushedAuthorizationRequestsToServerConfig.java */
export function addRequirePushedAuthorizationRequestsToServerConfig(
	server: ServerMetadata,
	...requirements: string[]
): void {
	server["require_pushed_authorization_requests"] = true;
	condition("AddRequirePushedAuthorizationRequestsToServerConfig", ...requirements).log(
		"Added require_pushed_authorization_requests to server configuration",
		{ value: true },
	);
}

/**
 * upstream: sequence/as/AddPARToServerConfiguration.java with
 * condition/as/par/AddPushedAuthorizationRequestEndpointToServerConfig.java,
 * AddRequirePushedAuthorizationRequestsToServerConfig.java
 */
export function addPARToServerConfiguration(server: ServerMetadata): void {
	addPushedAuthorizationRequestEndpointToServerConfig(server, "PAR-5");
	addRequirePushedAuthorizationRequestsToServerConfig(server, "PAR-5");
}

// ---------------------------------------------------------------------------------------------------------------
// the PAR request

/** The pushed form parameters (upstream "par_endpoint_http_request_params") */
export type ParParams = Record<string, unknown>;

/** upstream: condition/as/EnsurePAREndpointRequestDoesNotContainRequestUriParameter.java */
export function ensurePAREndpointRequestDoesNotContainRequestUriParameter(
	req: IncomingRequest,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsurePAREndpointRequestDoesNotContainRequestUriParameter", ...requirements);
	if (Object.hasOwn(req.body_form_params ?? {}, "request_uri")) {
		c.failure("PAR endpoint request contains a request_uri parameter");
	}
	c.success("PAR endpoint request does not contain a request_uri parameter");
}

/**
 * The `request` form parameter of the pushed request, parsed (decrypted with the server's encryption keys when it
 * is a JWE).
 *
 * upstream: condition/as/par/ExtractRequestObjectFromPAREndpointRequest.java (AbstractExtractRequestObject)
 */
export async function extractRequestObjectFromPAREndpointRequest(
	req: IncomingRequest,
	client: RpClient | null,
	serverEncryptionKeys: Jwks | null,
	...requirements: string[]
): Promise<ParsedJwt> {
	const c: Condition = condition("ExtractRequestObjectFromPAREndpointRequest", ...requirements);
	return processRequestObjectString(c, param(req.body_form_params ?? {}, "request"), client, serverEncryptionKeys);
}

/** upstream: condition/as/par/EnsureRequestObjectContainsCodeChallengeWhenUsingPAR.java */
export function ensureRequestObjectContainsCodeChallengeWhenUsingPAR(
	requestObject: ParsedJwt,
	...requirements: string[]
): CodeChallenge {
	const c: Condition = condition("EnsureRequestObjectContainsCodeChallengeWhenUsingPAR", ...requirements);
	const codeChallenge = param(requestObject.claims, "code_challenge");
	const codeChallengeMethod = param(requestObject.claims, "code_challenge_method");
	if (!codeChallenge) {
		c.failure("Missing required code_challenge parameter. PKCE is required when using PAR.");
	}
	if (!codeChallengeMethod) {
		c.failure("Missing required code_challenge_method parameter. PKCE is required when using PAR.");
	}
	if (codeChallengeMethod !== "S256") {
		c.failure("S256 is required for PKCE.", { code_challenge_method: codeChallengeMethod });
	}
	c.success("Found required PKCE parameters in request", {
		code_challenge_method: codeChallengeMethod,
		code_challenge: codeChallenge,
	});
	return { code_challenge: codeChallenge, code_challenge_method: codeChallengeMethod };
}

/** The PAR response (upstream "par_endpoint_response", "par_endpoint_response_headers", "par_endpoint_generated_request_uri") */
export interface ParResponse {
	response: Record<string, unknown>;
	headers: Record<string, string>;
	requestUri: string;
}

/**
 * A fresh request_uri (urn:ietf:params:oauth:request_uri:<uuid>) valid for 600 seconds; the x-fapi-interaction-id
 * header when one is known.
 *
 * upstream: condition/as/par/CreatePAREndpointResponse.java
 */
export function createPAREndpointResponse(fapiInteractionId: string | null, ...requirements: string[]): ParResponse {
	const requestUri = "urn:ietf:params:oauth:request_uri:" + randomUUID();
	const headers: Record<string, string> = {};
	if (fapiInteractionId) {
		headers["x-fapi-interaction-id"] = fapiInteractionId;
	}
	const response: Record<string, unknown> = { request_uri: requestUri, expires_in: 600 };
	// upstream logs the response without a message (logSuccess(args(...)))
	condition("CreatePAREndpointResponse", ...requirements).log({
		"Created PAR endpoint response": response,
		par_endpoint_response_headers: headers,
		result: "SUCCESS",
	});
	return { response, headers, requestUri };
}

// ---------------------------------------------------------------------------------------------------------------
// the authorization request that uses the request_uri

/** upstream: condition/as/par/EnsureAuthorizationRequestDoesNotContainRequestWhenUsingPAR.java */
export function ensureAuthorizationRequestDoesNotContainRequestWhenUsingPAR(httpParams: AuthorizationParams): void {
	const c: Condition = condition("EnsureAuthorizationRequestDoesNotContainRequestWhenUsingPAR");
	const requestObjectString = param(httpParams, "request");
	if (requestObjectString) {
		c.failure("Authorization request contains a request parameter when using PAR", { request: requestObjectString });
	}
	c.success("Request does not contain a request parameter");
}

/** upstream: condition/as/par/EnsureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR.java */
export function ensureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR(
	httpParams: AuthorizationParams,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR", ...requirements);
	const expectedParams = ["client_id", "request_uri"];
	const unexpectedParams = Object.keys(httpParams).filter((key) => !expectedParams.includes(key));
	if (unexpectedParams.length > 0) {
		c.failure(
			"Authorization request contains unexpected parameters when using PAR. Only 'client_id' and 'request_uri' " +
				"should be present, The inclusion of other parameters may result in data being unintentionally leaked to the " +
				"browser or in logs",
			{ "unexpected params": unexpectedParams },
		);
	}
	c.success("Request does not contain any unexpected parameters");
}

/**
 * The effective authorization request: the authorization request's parameters (request_uri removed), the pushed
 * parameters over them (the client authentication ones left out), JSON-valued parameters parsed, numeric ones
 * converted, and the request object's claims over everything.
 *
 * upstream: condition/as/CreateEffectiveAuthorizationPARRequestParameters.java
 * (CreateEffectiveAuthorizationRequestParameters)
 */
export function createEffectiveAuthorizationPARRequestParameters(
	httpParams: AuthorizationParams,
	parParams: ParParams,
	requestObject: ParsedJwt | null,
): AuthorizationParams {
	const c: Condition = condition("CreateEffectiveAuthorizationPARRequestParameters");
	const effective = structuredClone(httpParams);
	delete effective["request_uri"];
	// customizeEffectiveAuthorizationRequestParams: override with the unsigned PAR params
	delete effective["client_assertion"];
	delete effective["client_assertion_type"];
	delete effective["client_secret"];
	for (const [paramName, value] of Object.entries(parParams)) {
		effective[paramName] = structuredClone(value);
	}
	for (const name of ["authorization_details", "dcql_query", "client_metadata"]) {
		const value = effective[name];
		if (typeof value === "string") {
			try {
				effective[name] = JSON.parse(value);
			} catch (e) {
				c.failureFrom("Unable to parse " + name + " as JSON", e, { [name]: value });
			}
		}
	}
	// numeric query parameters arrive as strings (EnsureNumericRequestObjectClaimsAreNotNull.numericClaimNames)
	const maxAge = effective["max_age"];
	if (typeof maxAge === "string" && maxAge.trim() !== "" && !Number.isNaN(Number(maxAge))) {
		effective["max_age"] = Number(maxAge);
	}
	// the request object's claims override the request parameters
	if (requestObject != null) {
		Object.assign(effective, structuredClone(requestObject.claims));
	}
	c.success("Merged http request parameters with request object claims", {
		effective_authorization_endpoint_request: effective,
	});
	return effective;
}
