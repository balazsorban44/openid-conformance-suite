/**
 * Pushed authorization requests (RFC 9126): the request pushed to the PAR endpoint (the authorization request
 * parameters, or a signed request object), the call, the checks on the response and the request_uri it returns.
 *
 *   const parRequest = par.buildUnsignedPAREndpointRequest(request.params);
 *   await token.addClientAssertionToRequest(...)                 // client authentication on the PAR request
 *   const res = await par.callPAREndpoint(op, parRequest, "PAR-2.1");
 *   const requestUri = par.processParResponse(op, res);           // the checks, then the request_uri
 */
import { condition, type Condition } from "../suite/conditions.ts";
import { endpointResponse, HttpError, request, type EndpointResponse } from "../suite/http.ts";
import { parseJavaURI, URISyntaxException } from "../suite/uri.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { DpopState } from "./dpop.ts";
import { describeSuppliedNonce, dpopNonceResponseHeader } from "./dpop.ts";
import { ensureMinimumEntropy } from "./refresh-token.ts";

/**
 * A PAR request: form parameters and headers (upstream "pushed_authorization_request_form_parameters" /
 * "pushed_authorization_request_endpoint_request_headers")
 */
export interface ParRequest {
	form: Record<string, unknown>;
	headers: Record<string, string>;
}

/** The PAR endpoint's response (upstream "pushed_authorization_endpoint_response"; `json` is its body_json) */
export interface ParResponse extends EndpointResponse {
	json: Record<string, unknown> | null;
}

/** upstream: condition/client/BuildUnsignedPAREndpointRequest.java */
export function buildUnsignedPAREndpointRequest(params: Record<string, unknown>): ParRequest {
	const form = structuredClone(params);
	condition("BuildUnsignedPAREndpointRequest").success("Created PAR endpoint request", { ...form });
	return { form, headers: {} };
}

/** upstream: condition/client/BuildRequestObjectPostToPAREndpoint.java */
export function buildRequestObjectPostToPAREndpoint(requestObject: string): ParRequest {
	const form = { request: requestObject };
	// logSuccess(JsonObject): the form as the entry, no message
	condition("BuildRequestObjectPostToPAREndpoint").log({ ...form, result: "SUCCESS" });
	return { form, headers: {} };
}

/** What a variant of CallPAREndpoint (a subclass upstream) adds; see token.ts CallTokenEndpointOptions */
export interface CallPAREndpointOptions {
	conditionName?: string;
	/** the requirements the call site cites */
	requirements?: string[];
	/** upstream "par_endpoint_http_method" (the module that tries GET); default POST */
	method?: "POST" | "GET";
	onResponse?: (c: Condition, res: ParResponse) => void;
	parsedResponseLogSuffix?: (res: ParResponse) => string;
}

/**
 * POSTs the form to the PAR endpoint; any HTTP status is a response (the checks look at it).
 *
 * upstream: condition/client/CallPAREndpoint.java
 */
export async function callPAREndpoint(
	op: { metadata: ServerMetadata },
	req: ParRequest,
	opts: CallPAREndpointOptions = {},
): Promise<ParResponse> {
	const c: Condition = condition(opts.conditionName ?? "CallPAREndpoint", ...(opts.requirements ?? []));
	const form = new URLSearchParams();
	for (const [k, v] of Object.entries(req.form)) {
		form.append(k, typeof v === "object" && v !== null ? JSON.stringify(v) : String(v));
	}
	const method = opts.method ?? "POST";
	const endpoint = op.metadata["pushed_authorization_request_endpoint"];
	if (typeof endpoint !== "string" || !endpoint) {
		c.failure(
			"Couldn't find pushed_authorization_request_endpoint in server discovery document. This endpoint is required as you have selected to test pushed authorization requests.",
		);
	}
	let res;
	try {
		res = await request(c.name, {
			url: endpoint,
			method,
			headers: { ...req.headers, accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
			body: form.toString(),
		});
	} catch (e) {
		if (e instanceof HttpError) {
			const cause = e.cause instanceof Error ? e.cause.message : null;
			c.failureFrom("Call to pushed authorization request endpoint failed" + (cause ? " - " + cause : ""), e);
		}
		throw e;
	}
	const response: ParResponse = { ...endpointResponse("pushed authorization request", res), json: null };
	response.json =
		typeof response.body_json === "object" && response.body_json !== null && !Array.isArray(response.body_json)
			? (response.body_json as Record<string, unknown>)
			: null;
	opts.onResponse?.(c, response);
	if (method !== "POST") {
		// allow non-JSON responses when trying GET (which must be rejected)
		return response;
	}
	if (response.json == null) {
		c.failure("Pushed Authorization did not return a JSON object");
	}
	c.success(
		"Parsed pushed authorization request endpoint response" + (opts.parsedResponseLogSuffix?.(response) ?? ""),
		response.json,
	);
	return response;
}

/**
 * Calls the PAR endpoint and recognises a `use_dpop_nonce` error: the supplied DPoP-Nonce is kept for the retry
 * (`nonceError`, upstream "par_endpoint_dpop_nonce_error"); a nonce on a success is kept too (RFC 9449 8.2).
 *
 * upstream: condition/client/CallPAREndpointAllowingDpopNonceError.java
 */
export async function callPAREndpointAllowingDpopNonceError(
	op: { metadata: ServerMetadata },
	req: ParRequest,
	dpop: DpopState,
	...requirements: string[]
): Promise<{ response: ParResponse; nonceError: string | null }> {
	let nonceError: string | null = null;
	let suppliedDpopNonce: string | null = null;
	const response = await callPAREndpoint(op, req, {
		conditionName: "CallPAREndpointAllowingDpopNonceError",
		requirements,
		onResponse: (c, res) => {
			// checked whatever the status code was, so the violation is attributed to the response that carried it
			const nonceHeader = dpopNonceResponseHeader(res.headers);
			if (nonceHeader.violation != null) {
				c.failure(nonceHeader.violation, { headers: res.headers });
			}
			suppliedDpopNonce = nonceHeader.nonce;
			if (res.status === 400 && res.json?.["error"] === "use_dpop_nonce") {
				if (nonceHeader.nonce == null) {
					c.failure(
						"The PAR endpoint returned a 'use_dpop_nonce' error but supplied no DPoP-Nonce header, leaving no nonce to retry the request with.",
						{ headers: res.headers },
					);
				}
				dpop.authorizationServerNonce = nonceHeader.nonce;
				nonceError = nonceHeader.nonce;
			} else if (res.status >= 200 && res.status < 300 && nonceHeader.nonce != null) {
				// RFC 9449 §8.2: the server may rotate the DPoP nonce on every response and the client MUST use the
				// newly supplied value on subsequent requests
				dpop.authorizationServerNonce = nonceHeader.nonce;
			}
		},
		parsedResponseLogSuffix: () => " - " + describeSuppliedNonce(suppliedDpopNonce),
	});
	return { response, nonceError };
}

/** upstream: condition/client/CheckPAREndpointResponse201WithNoError.java */
export function checkPAREndpointResponse201WithNoError(res: ParResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckPAREndpointResponse201WithNoError", ...requirements);
	if (res.status !== 201) {
		c.failure("Invalid pushed authorization request endpoint response http status code", {
			expected: 201,
			actual: res.status,
		});
	}
	// UPSTREAM: getAsJsonObject() on a missing body_json is a NullPointerException
	const body = res.json as Record<string, unknown>;
	if (body["error"] != null) {
		c.failure("pushed authorization request endpoint error response.", { actual: JSON.stringify(body) });
	}
	c.success("pushed authorization request endpoint correct response.");
}

function str(o: Record<string, unknown> | null, key: string): string | null {
	const v = o?.[key];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/client/CheckForRequestUriValue.java */
export function checkForRequestUriValue(res: ParResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckForRequestUriValue", ...requirements);
	const requestUri = str(res.json, "request_uri");
	if (!requestUri) {
		c.failure("request_uri is missing or empty in pushed authorization response");
	}
	try {
		parseJavaURI(requestUri);
	} catch (e) {
		if (e instanceof URISyntaxException) {
			c.failure(
				"request_uri is malformed and does not seem to conform to RFC 2396: Uniform Resource Identifiers (URI): Generic Syntax",
			);
		}
		throw e;
	}
	c.success("Found valid request_uri ", { request_uri: requestUri });
}

/** upstream: condition/client/CheckForPARResponseExpiresIn.java */
export function checkForPARResponseExpiresIn(res: ParResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckForPARResponseExpiresIn", ...requirements);
	const expiresIn = res.json?.["expires_in"];
	// env.getLong: a number (truncated) or null
	if (typeof expiresIn !== "number") {
		c.failure("expires_in is missing or empty in pushed authorization response");
	}
	const seconds = Math.trunc(expiresIn);
	// do some minimum sanity checks on expiresIn - i.e. any value less than 5 seconds is stupid as it's unlikely to
	// give the client enough time to use the uri, and any value more than 1 year is equally bad. (These values are
	// relatively arbitrary choices, the standard just says 'its lifetime SHOULD be short')
	if (seconds < 5) {
		c.failure("expires_in too short and is unlikely to give the client enough time to use the request_uri");
	}
	if (seconds >= 365 * 24 * 60 * 60) {
		c.failure("expires_in too long, the specification requires it to be short", { expires_in: seconds });
	}
	c.success("Found expires_in ", { expires_in: seconds });
}

/** upstream: condition/client/ExtractRequestUriFromPARResponse.java */
export function extractRequestUriFromPARResponse(res: ParResponse): { requestUri: string; expiresIn: number } {
	const c: Condition = condition("ExtractRequestUriFromPARResponse");
	const requestUri = str(res.json, "request_uri");
	if (!requestUri) {
		c.failure("Couldn't find request_uri in " + "pushed authorization endpoint response");
	}
	const expiresIn = res.json?.["expires_in"];
	if (typeof expiresIn !== "number") {
		c.failure("Couldn't find expires_in in " + "pushed authorization endpoint response");
	}
	c.success("Extracted the request_uri: " + requestUri);
	return { requestUri, expiresIn: Math.trunc(expiresIn) };
}

/** upstream: condition/client/EnsureMinimumRequestUriEntropy.java (AbstractEnsureMinimumEntropy) */
export function ensureMinimumRequestUriEntropy(res: ParResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumRequestUriEntropy", ...requirements);
	const requestUri = str(res.json, "request_uri");
	if (!requestUri) {
		c.failure("Can't find requestUri ");
	}
	ensureMinimumEntropy(c, requestUri);
}

/** upstream: condition/client/AbstractEnsureSpecifiedErrorFromPushedAuthorizationEndpointResponse.java */
function ensureSpecifiedErrorFromPushedAuthorizationEndpointResponse(
	name: string,
	res: ParResponse,
	expected: string[],
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	if (res.status !== 400) {
		c.failure("Invalid pushed authorization request endpoint response http status code", {
			expected: 400,
			actual: res.status,
		});
	}
	const error = str(res.json, "error");
	if (!error) {
		c.failure("Expected 'error' field not found");
	}
	if (!expected.includes(error)) {
		c.failure("'error' field has unexpected value", { expected, actual: error });
	}
	c.success("Pushed Authorization Request Endpoint returned expected 'error' of '[" + expected.join(", ") + "]'", {
		error,
		expected,
	});
}

/** upstream: condition/client/EnsurePARInvalidRequestError.java */
export function ensurePARInvalidRequestError(res: ParResponse, ...requirements: string[]): void {
	ensureSpecifiedErrorFromPushedAuthorizationEndpointResponse(
		"EnsurePARInvalidRequestError",
		res,
		["invalid_request"],
		requirements,
	);
}

/** upstream: condition/client/EnsurePARInvalidRequestObjectError.java */
export function ensurePARInvalidRequestObjectError(res: ParResponse, ...requirements: string[]): void {
	ensureSpecifiedErrorFromPushedAuthorizationEndpointResponse(
		"EnsurePARInvalidRequestObjectError",
		res,
		["invalid_request_object"],
		requirements,
	);
}

/** upstream: condition/client/EnsurePARInvalidRequestOrInvalidDpopProof.java */
export function ensurePARInvalidRequestOrInvalidDpopProof(res: ParResponse, ...requirements: string[]): void {
	ensureSpecifiedErrorFromPushedAuthorizationEndpointResponse(
		"EnsurePARInvalidRequestOrInvalidDpopProof",
		res,
		["invalid_request", "invalid_dpop_proof"],
		requirements,
	);
}

/**
 * upstream: condition/client/CheckErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest.java
 * (CheckErrorFromParEndpointResponseError, AbstractCheckErrorFromParEndpointResponseError)
 */
export function checkErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest(
	res: ParResponse,
	...requirements: string[]
): void {
	const c: Condition = condition(
		"CheckErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequest",
		...requirements,
	);
	const key = "pushed_authorization_endpoint_response";
	// UPSTREAM: getAsJsonObject() on a missing body_json is a NullPointerException
	const body = res.json as Record<string, unknown>;
	const errorValue = body["error"];
	if (errorValue == null || typeof errorValue === "object") {
		c.failure("Expected 'error' field is not present in PAR response");
	}
	const error = String(errorValue);
	if (!error) {
		c.failure("Couldn't find error field");
	}
	const expected = ["invalid_request", "invalid_client"];
	if (!expected.includes(error)) {
		c.failure("'error' field has unexpected value", { expected, actual: error });
	}
	c.success(key + " error returned expected 'error' of '" + error + "'", { expected });
}
