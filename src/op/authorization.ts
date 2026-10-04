/**
 * The authorization request and response: building the request, sending the user's browser to the OP (the
 * configuration's browser automation logs in and consents), receiving the redirect back at the suite's
 * redirect_uri, and the checks on the authorization response.
 *
 *   const request = await block("Make request to authorization endpoint", () =>
 *     authz.createAuthorizationRequest(op, client));
 *   const response = await authz.authorize(op, request);
 *   await block("Verify authorization endpoint response", async () => {
 *     authz.checkAuthorizationResponse(op, request, response);
 *     const code = authz.extractAuthorizationCodeFromAuthorizationResponse(response);
 *     ...
 *   });
 */
import { createHash, randomInt } from "node:crypto";
import { condition, logModule, soft, type Condition } from "../suite/conditions.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import { htmlResponse, WaitTimeoutError, type IncomingRequest } from "../suite/server.ts";
import { toUriString } from "../suite/uri.ts";
import { JOSEException, ParseException } from "../suite/errors.ts";
import { getString, JavaHashMap } from "../suite/json.ts";
import { checkErrorDescriptionContainsCRLFTAB, validateErrorDescription, validateErrorUri } from "./endpoint.ts";
import { parseJwt, type ParsedJwt } from "../suite/jose.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { Op } from "./op.ts";
import type { Client, RegisteredClient } from "./registration.ts";
import { verifyJweEncryption, type AccessToken } from "./token.ts";

export interface AuthorizationRequest {
	/** The request parameters (upstream env "authorization_endpoint_request") */
	params: Record<string, unknown>;
	/** null when the test sends no state */
	state: string | null;
	nonce: string | null;
	redirectUri: string;
	/** The response_type sent, null when the test leaves it out */
	responseType: string | null;
	responseMode: "default" | "form_post";
	/** The URL the browser is sent to (upstream env "redirect_to_authorization_endpoint") */
	url: string;
}

export interface AuthorizationResponse {
	/**
	 * The authorization response parameters (upstream env "authorization_endpoint_response"): the form body for
	 * form_post, the query for the code flow (and when no response_type was sent), the fragment otherwise
	 */
	params: Record<string, unknown>;
	/** The redirect_uri query parameters (upstream "callback_query_params") */
	query: Record<string, unknown>;
	/** The redirect_uri fragment parameters (upstream "callback_params") */
	fragment: Record<string, unknown>;
	/** The form body of a POST to the redirect_uri (upstream "callback_body_form_params") */
	form?: Record<string, unknown>;
	method: string;
	headers: Record<string, string | string[]>;
}

function str(o: Record<string, unknown>, key: string): string | null {
	const v = o[key];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/client/CreateAuthorizationEndpointRequestFromClientInformation.java */
export function createAuthorizationEndpointRequestFromClientInformation(
	client: Client,
	redirectUri: string,
): Record<string, unknown> {
	const c: Condition = condition("CreateAuthorizationEndpointRequestFromClientInformation");
	if (!client.client_id) {
		c.failure("Couldn't find client ID");
	}
	if (!redirectUri) {
		c.failure("Couldn't find redirect URI");
	}
	const params: Record<string, unknown> = { client_id: client.client_id, redirect_uri: redirectUri };
	if (client.scope) {
		params["scope"] = client.scope;
	} else {
		c.log("No 'scope' parameter in client configuration - omitting scope from authorization request");
	}
	c.success("Created authorization endpoint request", { ...params });
	return params;
}

/** A random value of `length` URL-safe characters (CreateRandomStateValue / CreateRandomNonceValue) */
function randomValue(length: number): string {
	// over 10 characters: check that any url safe character can be used (JWTs are commonly used for state values)
	return length > 10 ? randomAlphanumeric(length - 4) + "-._~" : randomAlphanumeric(length);
}

/** upstream: condition/client/CreateRandomStateValue.java */
export function createRandomStateValue(length = 10): string {
	const state = randomValue(length);
	condition("CreateRandomStateValue").log("Created state value", { state, requested_state_length: length });
	return state;
}

/** upstream: condition/client/AddStateToAuthorizationEndpointRequest.java */
export function addStateToAuthorizationEndpointRequest(params: Record<string, unknown>, state: string): void {
	const c: Condition = condition("AddStateToAuthorizationEndpointRequest");
	if (!state) {
		c.failure("Couldn't find state value");
	}
	params["state"] = state;
	c.success("Added state parameter to request", { ...params });
}

/** upstream: condition/client/CreateRandomNonceValue.java */
export function createRandomNonceValue(length = 10): string {
	const nonce = randomValue(length);
	condition("CreateRandomNonceValue").log("Created nonce value", { nonce, requested_nonce_length: length });
	return nonce;
}

/** upstream: condition/client/AddNonceToAuthorizationEndpointRequest.java */
export function addNonceToAuthorizationEndpointRequest(params: Record<string, unknown>, nonce: string): void {
	const c: Condition = condition("AddNonceToAuthorizationEndpointRequest");
	if (!nonce) {
		c.failure("Couldn't find nonce value");
	}
	params["nonce"] = nonce;
	c.success("Added nonce parameter to request", { ...params });
}

/** upstream: condition/client/SetAuthorizationEndpointRequestResponseTypeFromEnvironment.java */
export function setAuthorizationEndpointRequestResponseType(
	params: Record<string, unknown>,
	responseType: string,
): void {
	const c: Condition = condition("SetAuthorizationEndpointRequestResponseTypeFromEnvironment");
	if (!responseType) {
		c.failure("No response_type found in config");
	}
	params["response_type"] = responseType;
	c.success("Added response_type parameter to request", { ...params });
}

/** upstream: condition/client/SetAuthorizationEndpointRequestResponseModeToFormPost.java */
export function setAuthorizationEndpointRequestResponseModeToFormPost(params: Record<string, unknown>): void {
	params["response_mode"] = "form_post";
	condition("SetAuthorizationEndpointRequestResponseModeToFormPost").log("Added response_mode parameter to request", {
		...params,
	});
}

/**
 * The URL with the request parameters in the query, sorted by name (objects and arrays as JSON).
 *
 * upstream: condition/client/BuildPlainRedirectToAuthorizationEndpoint.java
 */
export function buildPlainRedirectToAuthorizationEndpoint(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	...requirements: string[]
): string {
	const c: Condition = condition("BuildPlainRedirectToAuthorizationEndpoint", ...requirements);
	const endpoint = op.metadata.authorization_endpoint;
	if (!endpoint) {
		c.failure("Couldn't find authorization endpoint");
	}
	const query: [string, string][] = Object.keys(params)
		.sort()
		.map((key) => {
			const v = params[key];
			return [key, typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)];
		});
	const url = toUriString(endpoint, query);
	c.success("Sending to authorization endpoint", { redirect_to_authorization_endpoint: url, auth_request: params });
	return url;
}

export interface AuthorizationRequestOptions {
	/** default: the variant's response_type */
	responseType?: string;
	/** default: the variant's response_mode */
	responseMode?: "default" | "form_post";
	/**
	 * Steps of upstream's CreateAuthorizationRequestSteps a test leaves out, with the reason logged in their place
	 * (upstream `sequence.skip(Condition, reason)`), e.g. `{ response_type: "Miss out the response_type" }`
	 */
	omit?: { state?: string; nonce?: string; response_type?: string };
	/** CreateRandomStateValue's `requested_state_length` (default 10) */
	stateLength?: number;
	/** CreateRandomNonceValue's `requested_nonce_length` (default 10) */
	nonceLength?: number;
	/**
	 * Steps the module adds to the request after the standard ones, before the redirect URL is built (upstream
	 * `createAuthorizationRequestSequence().then(condition)`), e.g.
	 * `(params) => addPromptLoginToAuthorizationEndpointRequest(params, "OIDCC-3.1.2.1", "OIDCC-15.1")`
	 */
	steps?: (params: Record<string, unknown>) => void;
	/**
	 * The module's `createAuthorizationRedirect` (default: buildPlainRedirectToAuthorizationEndpoint), e.g. the
	 * request object modules' BuildRequestObjectBy{Value,Reference}RedirectToAuthorizationEndpoint
	 */
	buildRedirect?: (op: Pick<Op, "metadata">, params: Record<string, unknown>) => string;
}

/**
 * The authorization request of the OIDCC tests: client_id, redirect_uri, scope, a random state and nonce, the
 * response_type (and response_mode=form_post), and the URL to send the browser to.
 *
 * upstream: AbstractOIDCCServerTest.CreateAuthorizationRequestSteps + BuildPlainRedirectToAuthorizationEndpoint
 */
/** A request step the module leaves out (upstream `omit`): logged, not run */
const logOmitted = (name: string, reason: string): void => condition(name).log(reason);

export function createAuthorizationRequest(
	op: Pick<Op, "metadata" | "redirectUri" | "variant">,
	client: Client,
	opts: AuthorizationRequestOptions = {},
): AuthorizationRequest {
	const responseType = opts.responseType ?? op.variant.response_type;
	const responseMode = opts.responseMode ?? op.variant.response_mode;

	const params = createAuthorizationEndpointRequestFromClientInformation(client, op.redirectUri);
	let state: string | null = null;
	if (opts.omit?.state === undefined) {
		state = createRandomStateValue(opts.stateLength);
		addStateToAuthorizationEndpointRequest(params, state);
	} else {
		logOmitted("CreateRandomStateValue", opts.omit.state);
		logOmitted("AddStateToAuthorizationEndpointRequest", opts.omit.state);
	}
	let nonce: string | null = null;
	if (opts.omit?.nonce === undefined) {
		nonce = createRandomNonceValue(opts.nonceLength);
		addNonceToAuthorizationEndpointRequest(params, nonce);
	} else {
		// upstream's `.logOmitted(AddNonceToAuthorizationEndpointRequest, reason)` leaves CreateRandomNonceValue in place
		createRandomNonceValue(opts.nonceLength);
		logOmitted("AddNonceToAuthorizationEndpointRequest", opts.omit.nonce);
	}
	if (opts.omit?.response_type === undefined) {
		setAuthorizationEndpointRequestResponseType(params, responseType);
	} else {
		logOmitted("SetAuthorizationEndpointRequestResponseTypeFromEnvironment", opts.omit.response_type);
	}
	if (responseMode === "form_post") {
		setAuthorizationEndpointRequestResponseModeToFormPost(params);
	}
	opts.steps?.(params);
	const url = (opts.buildRedirect ?? buildPlainRedirectToAuthorizationEndpoint)(op, params);
	return {
		params,
		state,
		nonce,
		redirectUri: op.redirectUri,
		responseType: opts.omit?.response_type === undefined ? responseType : null,
		responseMode,
		url,
	};
}

/** upstream: condition/common/CreateRandomImplicitSubmitUrl.java */
export function createRandomImplicitSubmitUrl(baseUrl: string): { path: string; fullUrl: string } {
	const path = "implicit/" + randomAlphanumeric(20);
	const submit = { path, fullUrl: baseUrl + "/" + path };
	condition("CreateRandomImplicitSubmitUrl").success("Created random implicit submission URL", {
		implicit_submit: submit,
	});
	return submit;
}

/** upstream: condition/client/ExtractImplicitHashToCallbackResponse.java */
export function extractImplicitHashToCallbackResponse(implicitHash: string): Record<string, string> {
	const c: Condition = condition("ExtractImplicitHashToCallbackResponse");
	if (!implicitHash) {
		c.success("implicit_hash is empty", {});
		return {};
	}
	const parameters = [...new URLSearchParams(implicitHash.substring(1)).entries()];
	c.log("Extracted response from URL fragment", { parameters: parameters.map(([name, value]) => ({ name, value })) });
	const params = Object.fromEntries(parameters);
	c.success("Extracted the hash values", params);
	return params;
}

/**
 * Sends the browser to the authorization endpoint and waits for the redirect back to the redirect_uri. The
 * redirect_uri answers with upstream's implicit-callback page, which posts the URL fragment back to the suite, so
 * fragment responses arrive too. Resolves once the browser automation finished; rejects when the browser failed or
 * no response arrived in time.
 *
 * upstream: AbstractRedirectServerTestModule.performRedirect / handleCallback / handleImplicitSubmission
 */
export async function authorize(
	op: Pick<Op, "server" | "browser" | "baseUrl" | "log">,
	request: AuthorizationRequest,
	opts: { method?: "GET" | "POST"; timeoutSeconds?: number; callbackPath?: string } = {},
): Promise<AuthorizationResponse> {
	return (await redirect(op, request, { ...opts, placeholder: null })) as AuthorizationResponse;
}

/**
 * authorize() for a request the OP may answer with an error page instead of an error redirect: resolves with null
 * when the browser automation filled `placeholder` with a screenshot of the error page and no redirect came back.
 *
 * upstream: AbstractRedirectServerTestModule.performRedirectAndWaitForPlaceholdersOrCallback
 */
export async function authorizeExpectingErrorPageOrRedirect(
	op: Pick<Op, "server" | "browser" | "baseUrl" | "log">,
	request: AuthorizationRequest,
	placeholder: string,
	opts: { method?: "GET" | "POST"; timeoutSeconds?: number; callbackPath?: string } = {},
): Promise<AuthorizationResponse | null> {
	return redirect(op, request, { ...opts, placeholder });
}

async function redirect(
	op: Pick<Op, "server" | "browser" | "baseUrl" | "log">,
	request: AuthorizationRequest,
	opts: {
		method?: "GET" | "POST";
		timeoutSeconds?: number;
		placeholder: string | null;
		keepPlaceholder?: boolean;
		/** the path the OP redirects back to when it is not the suite's "callback" (upstream callbackEndpoint) */
		callbackPath?: string;
	},
): Promise<AuthorizationResponse | null> {
	const method = opts.method ?? "GET";
	logModule({ msg: "Redirecting to authorization endpoint", redirect_to: request.url, method, http: "redirect" });
	const done = new AbortController();
	let implicitSubmission: Promise<IncomingRequest> | null = null;
	const callback = op.server.waitFor(
		opts.callbackPath ?? "callback",
		() => {
			const submit = createRandomImplicitSubmitUrl(op.baseUrl);
			implicitSubmission = op.server.waitFor(submit.path, new Response(null, { status: 204 }), { signal: done.signal });
			implicitSubmission.catch(() => {});
			return htmlResponse(implicitCallbackPage(submit.fullUrl), 200, {
				"cache-control": "no-cache, no-store, must-revalidate",
				pragma: "no-cache",
			});
		},
		{ timeoutSeconds: opts.timeoutSeconds ?? 120, signal: done.signal },
	);
	callback.catch(() => {});
	const placeholderFilled = () =>
		opts.placeholder != null && !op.log.remainingPlaceholders().includes(opts.placeholder);
	const visit = op.browser.visit(request.url, { method, placeholder: opts.placeholder });
	try {
		// the browser automation usually ends after the callback page ran, so the callback is awaited either way (a
		// failing automation ends the wait); with a placeholder, a filled placeholder and no redirect is a result too
		const received = await Promise.race([
			callback,
			visit.then(() => (!opts.keepPlaceholder && placeholderFilled() ? null : callback)),
		]);
		if (received == null) {
			return null;
		}
		const submission = await (implicitSubmission as Promise<IncomingRequest> | null);
		await visit;
		if (opts.placeholder != null && !opts.keepPlaceholder) {
			// the OP redirected back instead of showing an error page: the screenshot is not needed
			op.log.fillPlaceholder(opts.placeholder, { image_no_longer_required: true });
		}
		const fragment = extractImplicitHashToCallbackResponse(submission?.body ?? "");
		const response: AuthorizationResponse = {
			params: {},
			query: received.query_string_params,
			fragment,
			form: received.body_form_params,
			method: received.method,
			headers: received.headers,
		};
		logModule({
			msg: "Authorization endpoint response captured",
			http: "redirect-in",
			http_method: response.method,
			url_query: response.query,
			url_fragment: response.fragment,
			headers: response.headers,
			post_body: response.form,
		});
		response.params =
			request.responseMode === "form_post"
				? (response.form ?? {})
				: request.responseType == null || request.responseType === "code"
					? response.query
					: response.fragment;
		return response;
	} finally {
		done.abort();
	}
}

/** upstream templates/implicitCallback.html: posts the URL fragment to `submitUrl`, then shows #submission_complete */
/** A string literal for inline JavaScript (no `</` that could end the script element) */
const js = (v: string): string => JSON.stringify(v).replaceAll("</", "<\\/");

function implicitCallbackPage(submitUrl: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>OIDF Conformance: Processing Implicit Callback</title></head>
<body>
<div><h1>Please wait...</h1><h2>Processing response from authorization server</h2>
<p id="complete" class="collapse">The response has been sent to the server for processing.</p></div>
<script>
var submitComplete = false;
function assumeComplete() {
	if (submitComplete) return;
	document.getElementById("complete").insertAdjacentHTML("beforeend", '<span id="submission_complete" hidden></span>');
}
document.addEventListener("DOMContentLoaded", function () {
	var hash = window.location.hash;
	var timeoutId = setTimeout(assumeComplete, 5000);
	function send(retry) {
		var xhr = new XMLHttpRequest();
		xhr.open("POST", ${js(submitUrl)}, true);
		xhr.setRequestHeader("Content-type", "text/plain");
		xhr.onload = function () {
			submitComplete = true;
			document.getElementById("complete").insertAdjacentHTML("beforeend", '<span id="submission_complete" hidden></span>');
		};
		xhr.onerror = function () {
			if (retry) {
				clearTimeout(timeoutId);
				timeoutId = setTimeout(assumeComplete, 5000);
				setTimeout(function () { send(false); }, 2000);
			}
		};
		xhr.send(hash);
	}
	send(true);
});
</script>
</body>
</html>`;
}

/** upstream: condition/client/CheckCallbackHttpMethodIsPost.java */
export function checkCallbackHttpMethodIsPost(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckCallbackHttpMethodIsPost", ...requirements);
	if (response.method !== "POST") {
		c.failure("The HTTP method used at redirect_uri is not 'POST'", { method: response.method });
	}
	c.success("HTTP method used at redirect_uri is 'POST'");
}

/** upstream: condition/client/CheckCallbackContentTypeIsFormUrlEncoded.java */
export function checkCallbackContentTypeIsFormUrlEncoded(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckCallbackContentTypeIsFormUrlEncoded", ...requirements);
	const contentType = response.headers["content-type"];
	const expected = "application/x-www-form-urlencoded";
	if (contentType == null) {
		c.failure("content-type header to redirect_uri is missing", { expected });
	}
	if (contentType !== expected) {
		c.failure("content-type header to redirect_uri does not have the expected value", {
			content_type: contentType,
			expected,
		});
	}
	c.success("content-type header to redirect_uri has the expected value", { content_type: contentType, expected });
}

/** upstream: condition/client/RejectAuthCodeInUrlQuery.java */
export function rejectAuthCodeInUrlQuery(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("RejectAuthCodeInUrlQuery", ...requirements);
	if (str(response.query, "code")) {
		c.failure(
			"Authorization code is present in URL query returned from authorization endpoint - hybrid/implicit flow require it to be returned in the URL fragment/hash only",
		);
	}
	c.success("Authorization code is not present in URL query returned from authorization endpoint");
}

/** upstream: condition/client/RejectErrorInUrlQuery.java */
export function rejectErrorInUrlQuery(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("RejectErrorInUrlQuery", ...requirements);
	if (str(response.query, "error")) {
		c.failure(
			"'error' is present in URL query returned from authorization endpoint - it should be returned in the URL fragment only",
		);
	}
	c.success("'error' is not present in URL query returned from authorization endpoint");
}

/**
 * The response arrived where the response mode says: a form POST for form_post, nothing in the query for
 * fragment responses.
 *
 * upstream: AbstractOIDCCServerTest.processCallback
 */
export function checkCallbackLocation(request: AuthorizationRequest, response: AuthorizationResponse): void {
	if (request.responseMode === "form_post") {
		soft(() => checkCallbackHttpMethodIsPost(response, "OAuth2-FP-2"));
		soft(() => checkCallbackContentTypeIsFormUrlEncoded(response, "OAuth2-FP-2"));
		soft(() => rejectAuthCodeInUrlQuery(response, "OIDCC-3.3.2.5"));
		soft(() => rejectErrorInUrlQuery(response, "OAuth2-RT-5"));
	} else if (request.responseType != null && request.responseType !== "code") {
		soft(() => rejectAuthCodeInUrlQuery(response, "OIDCC-3.3.2.5"));
		soft(() => rejectErrorInUrlQuery(response, "OAuth2-RT-5"));
	}
}

/**
 * The query parameters of the registered redirect_uri come back unchanged.
 *
 * upstream: condition/client/CheckMatchingCallbackParameters.java
 */
export function checkMatchingCallbackParameters(request: AuthorizationRequest, response: AuthorizationResponse): void {
	const c: Condition = condition("CheckMatchingCallbackParameters");
	// UriComponentsBuilder.fromUriString(redirect_uri).build().getQueryParams().toSingleValueMap(): raw values, first wins
	const params = new Map<string, string | null>();
	const query = /^[^?#]*\?([^#]*)/.exec(request.redirectUri)?.[1] ?? "";
	for (const pair of query.split("&")) {
		if (pair === "") {
			continue;
		}
		const eq = pair.indexOf("=");
		const name = eq === -1 ? pair : pair.substring(0, eq);
		if (!params.has(name)) {
			params.set(name, eq === -1 ? null : pair.substring(eq + 1));
		}
	}
	const verified: Record<string, unknown> = {};
	for (const [key, expected] of params) {
		const actual = str(response.query, key);
		if (expected !== actual) {
			c.failure(
				"The client should have been registered with a redirect uri that contains ?dummy1=lorem&dummy2=ipsum (as per instructions), and this url was passed as the redirect uri to the authorization endpoint. These parameters must be present in the redirect back, but they are not.",
				{ parameter: key, expected, actual },
			);
		}
		verified[key] = expected;
	}
	c.success("Callback parameters successfully verified", verified);
}

/** upstream: condition/client/ValidateIssIfPresentInAuthorizationResponse.java */
export function validateIssIfPresentInAuthorizationResponse(
	op: Pick<Op, "metadata">,
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIssIfPresentInAuthorizationResponse", ...requirements);
	const iss = str(response.params, "iss");
	if (iss == null) {
		c.log("No 'iss' value in authorization response.");
		return;
	}
	if (op.metadata.issuer !== iss) {
		c.failure("'iss' parameter in authorization response does not match server's issuer value.", {
			expected: op.metadata.issuer,
			actual: iss,
		});
	}
	c.success("'iss' parameter in authorization response matches server's issuer value.");
}

/** upstream: condition/client/CheckIfAuthorizationEndpointError.java */
export function checkIfAuthorizationEndpointError(response: AuthorizationResponse): void {
	const c: Condition = condition("CheckIfAuthorizationEndpointError");
	if (str(response.params, "error")) {
		c.failure(
			"The authorization was expected to succeed, but the server returned an error from the authorization endpoint",
			response.params,
		);
	}
	c.success("No error from authorization endpoint");
}

/** upstream: condition/client/CheckStateInAuthorizationResponse.java */
export function checkStateInAuthorizationResponse(
	request: AuthorizationRequest,
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckStateInAuthorizationResponse", ...requirements);
	const actual = str(response.params, "state");
	const expected = request.state;
	if (!expected) {
		if (!actual) {
			c.success("No state in response to check");
			return;
		}
		c.failure("No state value was sent, but a state in response was returned", { expected: expected ?? "", actual });
	}
	const error = str(response.params, "error");
	if (expected === actual) {
		c.success("State in response correctly returned", { state: actual });
	} else if (!actual && error === "invalid_request_object") {
		c.success(
			"State is missing from response; this is permitted when the returned error is 'invalid_request_object' and the state was contained in the request object",
		);
	} else if (!actual && error === "invalid_request_uri") {
		c.success(
			"State is missing from response; this is permitted when the returned error is 'invalid_request_uri' and the state was contained in the par request",
		);
	} else if (!actual) {
		c.failure("State was passed in request, but is missing from response (or returned in the wrong place)", {
			expected,
			actual: actual ?? "",
		});
	} else {
		c.failure("State in response did not match", { expected, actual });
	}
}

/** upstream: condition/client/ExtractAuthorizationCodeFromAuthorizationResponse.java */
export function extractAuthorizationCodeFromAuthorizationResponse(response: AuthorizationResponse): string {
	const c: Condition = condition("ExtractAuthorizationCodeFromAuthorizationResponse");
	const code = str(response.params, "code");
	if (!code) {
		c.failure("Couldn't find authorization code in authorization_endpoint_response, 'code' parameter is missing/empty");
	}
	c.success("Found authorization code", { code });
	return code;
}

/**
 * The checks on a successful authorization response, in upstream's order (the caller then extracts what the
 * response type returns, e.g. extractAuthorizationCodeFromAuthorizationResponse for the code flow).
 *
 * upstream: AbstractOIDCCServerTest.processCallback + onAuthorizationCallbackResponse up to
 * CheckStateInAuthorizationResponse
 */
export function checkAuthorizationResponse(
	op: Pick<Op, "metadata">,
	request: AuthorizationRequest,
	response: AuthorizationResponse,
	/** afterCallbackLocation: what a module's onAuthorizationCallbackResponse override does before calling super */
	opts: { afterCallbackLocation?: () => void } = {},
): void {
	checkCallbackLocation(request, response);
	opts.afterCallbackLocation?.();
	soft(() => checkMatchingCallbackParameters(request, response));
	soft(() => validateIssIfPresentInAuthorizationResponse(op, response, "OAuth2-iss-2"));
	checkIfAuthorizationEndpointError(response);
	soft(() => checkStateInAuthorizationResponse(request, response));
}

/** upstream: condition/client/EnsureMinimumAuthorizationCodeLength.java */
export function ensureMinimumAuthorizationCodeLength(code: string | null, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumAuthorizationCodeLength", ...requirements);
	const requiredLength = 128;
	if (!code) {
		c.failure("Can't find authorization code");
	}
	const bitLength = Buffer.byteLength(code, "utf8") * 8;
	if (bitLength < requiredLength) {
		c.failure("Authorization code is not long enough", { required_bits: requiredLength, actual_bits: bitLength });
	}
	c.success("Authorization code is of sufficient length", { required: requiredLength, actual: bitLength });
}

/**
 * Shannon entropy of a string in bits per character, summed in the iteration order of Java's HashMap<Character,
 * Integer> so the floating point result is the same as upstream's (upstream: condition/AbstractEnsureMinimumEntropy.java).
 */
export function shannonEntropy(s: string): number {
	const occ = new Map<string, number>();
	for (const ch of s.split("")) {
		occ.set(ch, (occ.get(ch) ?? 0) + 1);
	}
	let capacity = 16;
	while (occ.size > capacity * 0.75) {
		capacity *= 2;
	}
	const counts = [...occ.entries()]
		.map(([ch, count], insertion) => ({ bucket: ch.charCodeAt(0) & (capacity - 1), insertion, count }))
		.sort((a, b) => a.bucket - b.bucket || a.insertion - b.insertion)
		.map((x) => x.count);
	let e = 0;
	for (const count of counts) {
		const p = count / s.length;
		e += p * (Math.log(p) / Math.log(2));
	}
	return -e;
}

/** upstream: condition/client/EnsureMinimumAuthorizationCodeEntropy.java (AbstractEnsureMinimumEntropy) */
export function ensureMinimumAuthorizationCodeEntropy(code: string | null, ...requirements: string[]): void {
	const c: Condition = condition("EnsureMinimumAuthorizationCodeEntropy", ...requirements);
	// 128 bits are required; entropy cannot be measured accurately, so some slop is allowed for
	const requiredEntropy = 96;
	if (!code) {
		c.failure("Can't find authorization code");
	}
	const entropy = shannonEntropy(code) * code.length;
	const fields = { value: code, expected: requiredEntropy, actual: entropy };
	if (entropy <= requiredEntropy) {
		c.failure(
			"Calculated shannon entropy does not seem to meet minimum required entropy (i.e. item is too short, or not random enough)",
			fields,
		);
	}
	c.success("Calculated shannon entropy seems sufficient", fields);
}

/** upstream: condition/client/EnsureErrorFromAuthorizationEndpointResponse.java */
export function ensureErrorFromAuthorizationEndpointResponse(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureErrorFromAuthorizationEndpointResponse", ...requirements);
	if (!("error" in response.params)) {
		c.failure("Authorization server was expected to return an error but did not", response.params);
	}
	c.success("Authorization endpoint returned an error", response.params);
}

/** upstream: condition/client/RejectAuthCodeInAuthorizationEndpointResponse.java */
export function rejectAuthCodeInAuthorizationEndpointResponse(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("RejectAuthCodeInAuthorizationEndpointResponse", ...requirements);
	if (response.query["code"] != null) {
		c.failure("Authorization code is present in URL query but an error was expected");
	}
	if (response.fragment["code"] != null) {
		c.failure("Authorization code is present in URL fragment returned from but an error was expected");
	}
	c.success("Authorization code is not present in authorization endpoint response");
}

/** upstream: condition/client/CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint.java */
export function checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(
	response: AuthorizationResponse,
	opts: { expectDummy1Dummy2?: boolean } = {},
	...requirements: string[]
): void {
	const c: Condition = condition(
		"CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint",
		...requirements,
	);
	const expected = ["error", "error_description", "error_uri", "state", "session_state", "iss"];
	if (opts.expectDummy1Dummy2) {
		expected.push("dummy1", "dummy2");
	}
	if (!("error" in response.params)) {
		c.failure("Authorization server was expected to return an error but did not", response.params);
	}
	const unexpected = Object.fromEntries(Object.entries(response.params).filter(([k]) => !expected.includes(k)));
	if (Object.keys(unexpected).length > 0) {
		c.failure(
			"error response includes unexpected parameters. This may indicate the authorization server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
			unexpected,
		);
	}
	c.success("error response includes only expected parameters", response.params);
}

/**
 * The generic checks on an error response from the authorization endpoint; the caller still checks for the
 * specific error code its scenario expects.
 *
 * upstream: AbstractOIDCCServerTest.performGenericAuthorizationEndpointErrorResponseValidation
 */
export function checkAuthorizationErrorResponse(
	op: Pick<Op, "metadata">,
	request: AuthorizationRequest,
	response: AuthorizationResponse,
): void {
	const name = "authorization_endpoint_response";
	soft(() => checkStateInAuthorizationResponse(request, response));
	soft(() => validateIssIfPresentInAuthorizationResponse(op, response, "OAuth2-iss-2"));
	soft(() => ensureErrorFromAuthorizationEndpointResponse(response, "OIDCC-3.1.2.6"));
	soft(() => rejectAuthCodeInAuthorizationEndpointResponse(response, "OIDCC-3.1.2.6"));
	soft(
		() => checkForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint(response, {}, "OIDCC-3.1.2.6"),
		"warning",
	);
	soft(
		() =>
			checkErrorDescriptionContainsCRLFTAB(
				"CheckErrorDescriptionFromAuthorizationEndpointResponseErrorContainsCRLFTAB",
				name,
				response.params,
				"RFC6749-4.1.2.1",
			),
		"warning",
	);
	soft(() =>
		validateErrorDescription(
			"ValidateErrorDescriptionFromAuthorizationEndpointResponseError",
			name,
			response.params,
			"RFC6749-4.1.2.1",
		),
	);
	soft(() =>
		validateErrorUri(
			"ValidateErrorUriFromAuthorizationEndpointResponseError",
			name,
			response.params,
			"RFC6749-4.1.2.1",
		),
	);
}

/** upstream: condition/client/CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType.java */
export function checkErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition(
		"CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType",
		...requirements,
	);
	const expected = ["unsupported_response_type", "invalid_request"];
	const error = str(response.params, "error");
	if (!error) {
		c.failure("Expected 'error' field not found");
	}
	if (!expected.includes(error)) {
		c.failure("'error' field has unexpected value", { expected, actual: error });
	}
	c.success("Authorization endpoint returned expected error", { expected, actual: error });
}

/**
 * A REVIEW entry asking for a screenshot of the error page the OP shows for a request without response_type; the
 * browser automation fills it ("update-image-placeholder"). Returns the placeholder to pass to authorize().
 *
 * upstream: condition/common/ExpectResponseTypeMissingErrorPage.java
 */
export function expectResponseTypeMissingErrorPage(...requirements: string[]): string {
	const placeholder = randomAlphanumeric(10);
	condition("ExpectResponseTypeMissingErrorPage", ...requirements).review(
		"Upload a screenshot of the error page showing a missing response type error.",
		{ upload: placeholder },
	);
	return placeholder;
}

/**
 * buildPlainRedirectToAuthorizationEndpoint with the parameters in reverse alphabetical order, to test that the
 * OP handles different parameter orderings.
 *
 * upstream: condition/client/BuildPlainRedirectToAuthorizationEndpointReorderedParams.java
 */
export function buildPlainRedirectToAuthorizationEndpointReorderedParams(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
): string {
	const c: Condition = condition("BuildPlainRedirectToAuthorizationEndpointReorderedParams");
	const endpoint = op.metadata.authorization_endpoint;
	if (!endpoint) {
		c.failure("Couldn't find authorization endpoint");
	}
	const query: [string, string][] = Object.keys(params)
		.sort((a, b) => (a < b ? 1 : a > b ? -1 : 0))
		.map((key) => {
			const v = params[key];
			return [key, typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)];
		});
	const url = toUriString(endpoint, query);
	c.success("Sending to authorization endpoint", { redirect_to_authorization_endpoint: url, auth_request: params });
	return url;
}

/** upstream: condition/client/ReverseScopeOrderInAuthorizationEndpointRequest.java (AbstractReverseScopeOrder) */
export function reverseScopeOrderInAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("ReverseScopeOrderInAuthorizationEndpointRequest", ...requirements);
	const scope = params["scope"];
	if (scope == null || scope === "") {
		c.failure("no scope found");
	}
	// Java's String.split drops trailing empty strings, JS keeps them
	const scopes = String(scope).split(" ");
	while (scopes.length > 0 && scopes[scopes.length - 1] === "") {
		scopes.pop();
	}
	if (scopes.length < 2) {
		c.failure("'scope' in the configuration must contain more than one scope to run this test");
	}
	const reversed = scopes.toReversed().join(" ");
	params["scope"] = reversed;
	c.log("Reversed order of scopes in authorization_endpoint_request", { original: scope, reversed });
}

/** upstream: condition/client/AddClaimsLocalesSeToAuthorizationEndpointRequest.java */
export function addClaimsLocalesSeToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["claims_locales"] = "se";
	condition("AddClaimsLocalesSeToAuthorizationEndpointRequest", ...requirements).success(
		"Added claims_locales=se to authorization endpoint request",
		{ ...params },
	);
}

/** upstream: condition/client/AddDisplayPageToAuthorizationEndpointRequest.java */
export function addDisplayPageToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["display"] = "page";
	condition("AddDisplayPageToAuthorizationEndpointRequest", ...requirements).log(
		"Added display=page to authorization endpoint request",
		{ ...params },
	);
}

/** upstream: condition/client/AddDisplayPopupToAuthorizationEndpointRequest.java */
export function addDisplayPopupToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["display"] = "popup";
	condition("AddDisplayPopupToAuthorizationEndpointRequest", ...requirements).log(
		"Added display=popup to authorization endpoint request",
		{ ...params },
	);
}

/** upstream: condition/client/AddUiLocalesFromConfigurationToAuthorizationEndpointRequest.java */
export function addUiLocalesFromConfigurationToAuthorizationEndpointRequest(
	op: Pick<Op, "config">,
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("AddUiLocalesFromConfigurationToAuthorizationEndpointRequest", ...requirements);
	const server = op.config["server"] as Record<string, unknown> | undefined;
	let uiLocales = server?.["ui_locales"];
	let msg: string;
	if (typeof uiLocales !== "string" || uiLocales === "") {
		uiLocales = "se";
		msg = "No ui_locales in test configuration, added ui_locales=se to authorization endpoint request";
	} else {
		msg = "Added ui_locales from test configuration to authorization endpoint request";
	}
	params["ui_locales"] = uiLocales;
	c.success(msg, { ...params });
}

/** upstream: condition/client/AddLoginHintFromConfigurationToAuthorizationEndpointRequest.java */
export function addLoginHintFromConfigurationToAuthorizationEndpointRequest(
	op: Pick<Op, "config" | "metadata">,
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("AddLoginHintFromConfigurationToAuthorizationEndpointRequest", ...requirements);
	const server = op.config["server"] as Record<string, unknown> | undefined;
	let loginHint = server?.["login_hint"];
	let msg: string;
	if (typeof loginHint !== "string" || loginHint === "") {
		const issuer = op.metadata.issuer;
		try {
			loginHint = "buffy@" + new URL(issuer as string).hostname;
		} catch (e) {
			c.failureFrom("Couldn't parse issuer as URL", e, { issuer });
		}
		msg =
			"No login_hint in test configuration, created one based on issuer and added login_hint to authorization endpoint request";
	} else {
		msg = "Added login_hint from test configuration to authorization endpoint request";
	}
	params["login_hint"] = loginHint;
	c.success(msg, { ...params });
}

/** upstream: condition/client/AddPromptNoneToAuthorizationEndpointRequest.java */
export function addPromptNoneToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["prompt"] = "none";
	condition("AddPromptNoneToAuthorizationEndpointRequest", ...requirements).success(
		"Added prompt=none to authorization endpoint request",
		{ ...params },
	);
}

/** upstream: condition/client/AddIdTokenHintFromFirstLoginToAuthorizationEndpointRequest.java */
export function addIdTokenHintFromFirstLoginToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	firstIdToken: Pick<ParsedJwt, "value">,
	...requirements: string[]
): void {
	params["id_token_hint"] = firstIdToken.value;
	condition("AddIdTokenHintFromFirstLoginToAuthorizationEndpointRequest", ...requirements).success(
		"Added id_token_hint to authorization endpoint request",
		{ ...params },
	);
}

function isObject(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Requests a claim from `location` of the `claims` request parameter.
 *
 * upstream: condition/client/AbstractAddClaimToAuthorizationEndpointRequest.addClaim (the id_token / userinfo
 * "essential name" conditions below)
 */
function addClaimToAuthorizationEndpointRequest(
	name: string,
	params: Record<string, unknown>,
	location: "id_token" | "userinfo",
	claim: string,
	value: string | null,
	essential: boolean,
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	const invalid = (what: string): never =>
		c.failure("Invalid " + what + " entry in authorization_endpoint_request", {
			authorization_endpoint_request: params,
		});
	let claims: Record<string, unknown>;
	if ("claims" in params) {
		const existing = params["claims"];
		claims = isObject(existing) ? existing : invalid("claims");
	} else {
		claims = {};
		params["claims"] = claims;
	}
	let forLocation: Record<string, unknown>;
	if (location in claims) {
		const existing = claims[location];
		forLocation = isObject(existing) ? existing : invalid(location);
	} else {
		forLocation = {};
		claims[location] = forLocation;
	}
	const body: Record<string, unknown> = {};
	if (value != null) {
		body["value"] = value;
	}
	body["essential"] = essential;
	forLocation[claim] = body;
	c.success("Added " + claim + " claim to authorization_endpoint_request", { authorization_endpoint_request: params });
}

/** upstream: condition/client/AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest.java */
export function addUserInfoEssentialNameClaimToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	addClaimToAuthorizationEndpointRequest(
		"AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest",
		params,
		"userinfo",
		"name",
		null,
		true,
		requirements,
	);
}

/**
 * The OP answered a prompt=none request for a user who is not logged in with one of the errors that say a user
 * interface is needed (https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
 *
 * upstream: condition/client/CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface.java
 */
export function checkErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface", ...requirements);
	const permitted = ["interaction_required", "login_required", "account_selection_required", "consent_required"];
	const error = str(response.params, "error");
	if (!error) {
		c.failure("Expected 'error' field not found");
	}
	if (!permitted.includes(error)) {
		c.failure("'error' field has an unexpected value", { permitted, actual: error });
	}
	c.success("Authorization endpoint returned one of the permitted errors", { permitted, actual: error });
}

/** upstream: condition/client/AddPromptLoginToAuthorizationEndpointRequest.java */
export function addPromptLoginToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["prompt"] = "login";
	condition("AddPromptLoginToAuthorizationEndpointRequest", ...requirements).success(
		"Added prompt=login to authorization endpoint request",
		{ ...params },
	);
}

/** upstream: condition/client/AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess.java */
export function addPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition(
		"AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess",
		...requirements,
	);
	if (params["scope"] == null) {
		c.success("Not adding prompt=consent as the authorization endpoint request does not contain a scope");
		return;
	}
	if (!String(params["scope"]).includes("offline_access")) {
		c.success("Not adding prompt=consent as the scope in the configuration does not contain offline_access");
		return;
	}
	params["prompt"] = "consent";
	c.success("Added prompt=consent to authorization endpoint request", { ...params });
}

/** The shared body of the AddMaxAge1/10000/15000ToAuthorizationEndpointRequest conditions below */
function addMaxAgeToAuthorizationEndpointRequest(
	name: string,
	params: Record<string, unknown>,
	maxAge: number,
	requirements: string[],
): void {
	params["max_age"] = maxAge;
	condition(name, ...requirements).success("Added max_age=" + maxAge + " to authorization endpoint request", {
		...params,
	});
}

/** upstream: condition/client/AddMaxAge1ToAuthorizationEndpointRequest.java */
export function addMaxAge1ToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	addMaxAgeToAuthorizationEndpointRequest("AddMaxAge1ToAuthorizationEndpointRequest", params, 1, requirements);
}

/** upstream: condition/client/AddMaxAge10000ToAuthorizationEndpointRequest.java */
export function addMaxAge10000ToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	addMaxAgeToAuthorizationEndpointRequest("AddMaxAge10000ToAuthorizationEndpointRequest", params, 10000, requirements);
}

/** upstream: condition/client/AddMaxAge15000ToAuthorizationEndpointRequest.java */
export function addMaxAge15000ToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	addMaxAgeToAuthorizationEndpointRequest("AddMaxAge15000ToAuthorizationEndpointRequest", params, 15000, requirements);
}

/** upstream: condition/client/AddExtraFoobarToAuthorizationEndpointRequest.java */
export function addExtraFoobarToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["extra"] = "foobar";
	condition("AddExtraFoobarToAuthorizationEndpointRequest", ...requirements).log(
		"Added extra=foobar to authorization endpoint request",
		{ ...params },
	);
}

/**
 * acr_values: every value of the OP's acr_values_supported, else the `acr_values` of a static server configuration,
 * else "1 2".
 *
 * upstream: condition/client/OIDCCAddAcrValuesToAuthorizationEndpointRequest.java
 */
export function oidccAddAcrValuesToAuthorizationEndpointRequest(
	op: Pick<Op, "metadata">,
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("OIDCCAddAcrValuesToAuthorizationEndpointRequest", ...requirements);
	const acrValuesSupported = op.metadata["acr_values_supported"];
	const acrValues = op.metadata["acr_values"];
	let acrValuesRequest: string;
	let msg: string;
	if (acrValuesSupported != null) {
		// include all values server supports
		acrValuesRequest = (acrValuesSupported as string[]).join(" ");
		msg =
			"Added all acr values from server discovery document's acr_values_supportedto acr_values in authorization endpoint request.";
	} else if (typeof acrValues === "string" && acrValues !== "") {
		// server doesn't support discovery; use user supplied value from test config
		acrValuesRequest = acrValues;
		msg = "Added acr_values from test configuration";
	} else {
		// include just '1' and '2' as per the python suite (oidctest op/func.py)
		acrValuesRequest = "1 2";
		msg =
			"server discovery document does not contain acr_values_supported (or, for static server config, test configuration does not contain acr_values) so setting acr_values in authorization endpoint request to '1 2'.";
	}
	params["acr_values"] = acrValuesRequest;
	c.success(msg, { request: { ...params }, acr_values: acrValuesRequest });
}

/**
 * A REVIEW entry asking for a screenshot of the second login page; the browser automation fills it
 * ("update-image-placeholder"). Returns the placeholder to pass to authorizeWithPlaceholder().
 *
 * upstream: condition/client/ExpectSecondLoginPage.java
 */
export function expectSecondLoginPage(...requirements: string[]): string {
	const placeholder = randomAlphanumeric(10);
	condition("ExpectSecondLoginPage", ...requirements).review(
		"The server must ask the user to login for a second time; a screenshot of this must be uploaded.",
		{ upload: placeholder },
	);
	return placeholder;
}

/**
 * A REVIEW entry asking for a screenshot of the redirect URI error page; see expectSecondLoginPage().
 *
 * upstream: condition/common/ExpectRedirectUriErrorPage.java
 */
export function expectRedirectUriErrorPage(...requirements: string[]): string {
	const placeholder = randomAlphanumeric(10);
	condition("ExpectRedirectUriErrorPage", ...requirements).review("Show redirect URI error page", {
		upload: placeholder,
	});
	return placeholder;
}

/**
 * A redirect_uri below the suite's callback that cannot have been registered: `<base url>/callback/<random>`.
 *
 * upstream: condition/client/CreateBadRedirectUriByAppending.java
 */
export function createBadRedirectUriByAppending(baseUrl: string): { redirectUri: string; badRedirectPath: string } {
	const c: Condition = condition("CreateBadRedirectUriByAppending");
	if (baseUrl === "") {
		c.failure("Base URL is empty");
	}
	// create a random redirect URI, by appending a random path, which shouldn't be registered with the server
	const badRedirectPath = randomAlphanumeric(10);
	const redirectUri = baseUrl + "/callback/" + badRedirectPath;
	c.success("Created a randomised (and hence unregistered) redirect URI", { redirect_uri: redirectUri });
	return { redirectUri, badRedirectPath };
}

/**
 * The OP answered the POST to the authorization endpoint by calling the redirect_uri (`response` is null when it did
 * not within the test's 30 seconds).
 *
 * upstream: condition/client/ExpectRedirectUriHasBeenCalled.java
 */
export function expectRedirectUriHasBeenCalled(
	response: AuthorizationResponse | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ExpectRedirectUriHasBeenCalled", ...requirements);
	if (response == null) {
		c.failure(
			"The OpenID Connect core specification states that 'Authorization Servers MUST support the use of the HTTP GET and POST methods defined in RFC 7231 at the Authorization Endpoint'. In the conformance suite, failure to correctly respond to an HTTP POST request to the authorization endpoint within 30 seconds is considered a WARNING.",
		);
	}
}

/** upstream: condition/client/EnsureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri.java */
export function ensureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri(): never {
	return condition("EnsureOPDoesNotUseDefaultRedirectUriInCaseOfInvalidRedirectUri").failure(
		"An invalid redirect_uri was included in the authorization request but the OP redirected to a default redirect_uri instead of displaying an error page",
	);
}

/** upstream: condition/client/AddInvalidRedirectUriToAuthorizationRequest.java */
export function addInvalidRedirectUriToAuthorizationRequest(
	params: Record<string, unknown>,
	redirectUri: string,
	...requirements: string[]
): void {
	const url = new URL(redirectUri);
	url.pathname += "_invalid";
	const invalidUri = url.toString();
	delete params["redirect_uri"];
	params["redirect_uri"] = invalidUri;
	condition("AddInvalidRedirectUriToAuthorizationRequest", ...requirements).success(
		"Added invalid redirect_uri to authorization endpoint request",
		{ redirect_uri: invalidUri },
	);
}

/** upstream: condition/client/CreateRandomCodeVerifier.java */
export function createRandomCodeVerifier(...requirements: string[]): string {
	// RFC7636-4.1: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", 43 to 128 characters. Not base64url of random
	// bytes, to test the full range of permitted characters (including . and ~).
	const allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
	// test maximum permitted length
	let verifier = "";
	for (let i = 0; i < 128; i++) {
		verifier += allowedChars[randomInt(allowedChars.length)];
	}
	condition("CreateRandomCodeVerifier", ...requirements).log("Created code_verifier value", {
		code_verifier: verifier,
	});
	return verifier;
}

/** upstream: condition/client/CreateS256CodeChallenge.java */
export function createS256CodeChallenge(
	verifier: string,
	...requirements: string[]
): { codeChallenge: string; codeChallengeMethod: "S256" } {
	const c: Condition = condition("CreateS256CodeChallenge", ...requirements);
	if (!verifier) {
		c.failure("code_verifier was null or empty");
	}
	const codeChallenge = createHash("sha256").update(Buffer.from(verifier, "ascii")).digest().toString("base64url");
	c.log("Created code_challenge value", { code_challenge: codeChallenge });
	return { codeChallenge, codeChallengeMethod: "S256" };
}

/** upstream: condition/client/AddCodeChallengeToAuthorizationEndpointRequest.java */
export function addCodeChallengeToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	codeChallenge: string,
	codeChallengeMethod: string,
	...requirements: string[]
): void {
	const c: Condition = condition("AddCodeChallengeToAuthorizationEndpointRequest", ...requirements);
	if (!codeChallenge) {
		c.failure("Couldn't find code_challenge value");
	}
	// UPSTREAM: checks code_challenge again instead of code_challenge_method
	if (!codeChallenge) {
		c.failure("Couldn't find code_challenge_method value");
	}
	params["code_challenge"] = codeChallenge;
	params["code_challenge_method"] = codeChallengeMethod;
	c.success("Added code_challenge and code_challenge_method parameters to request", { ...params });
}

/**
 * A random code_verifier (RFC7636-4.1) and its S256 challenge in the authorization request (RFC7636-4.2, 4.3);
 * returns the code_verifier for the token request.
 *
 * upstream: sequence/client/SetupPkceAndAddToAuthorizationRequest.java
 */
export function setupPkceAndAddToAuthorizationRequest(params: Record<string, unknown>): string {
	const codeVerifier = createRandomCodeVerifier("RFC7636-4.1");
	const { codeChallenge, codeChallengeMethod } = createS256CodeChallenge(codeVerifier, "RFC7636-4.2");
	addCodeChallengeToAuthorizationEndpointRequest(params, codeChallenge, codeChallengeMethod, "RFC7636-4.3");
	return codeVerifier;
}

/**
 * authorize() for a request whose test created a placeholder (a screenshot to upload, e.g. of the second login page)
 * for a flow that still redirects back: the placeholder stays pending (result REVIEW) unless the browser automation
 * fills it.
 *
 * upstream: AbstractRedirectServerTestModule.performRedirectWithPlaceholder
 */
export async function authorizeWithPlaceholder(
	op: Pick<Op, "server" | "browser" | "baseUrl" | "log">,
	request: AuthorizationRequest,
	placeholder: string,
	opts: { method?: "GET" | "POST"; timeoutSeconds?: number } = {},
): Promise<AuthorizationResponse> {
	return (await redirect(op, request, { ...opts, placeholder, keepPlaceholder: true })) as AuthorizationResponse;
}

/**
 * authorize() that resolves with null when the OP did not call the redirect_uri within `timeoutSeconds` (the
 * test's own timer, upstream OIDCCEnsurePostRequestSucceeds.startWaitingForTimeout).
 */
export async function authorizeWithinSeconds(
	op: Pick<Op, "server" | "browser" | "baseUrl" | "log">,
	request: AuthorizationRequest,
	timeoutSeconds: number,
	opts: { method?: "GET" | "POST" } = {},
): Promise<AuthorizationResponse | null> {
	try {
		return await authorize(op, request, { ...opts, timeoutSeconds });
	} catch (e) {
		if (e instanceof WaitTimeoutError) {
			return null;
		}
		throw e;
	}
}

/** upstream: condition/client/ExpectRedirectUriMissingErrorPage.java; returns the placeholder to wait for */
export function expectRedirectUriMissingErrorPage(...requirements: string[]): string {
	const placeholder = randomAlphanumeric(10);
	condition("ExpectRedirectUriMissingErrorPage", ...requirements).review(
		"Show an error page saying the redirect uri is missing from the request.",
		{ upload: placeholder },
	);
	return placeholder;
}

/** upstream: condition/client/RemoveRedirectUriFromAuthorizationEndpointRequest.java */
export function removeRedirectUriFromAuthorizationEndpointRequest(params: Record<string, unknown>): void {
	delete params["redirect_uri"];
	// upstream logs nothing: the framework notes that the condition ran
	condition("RemoveRedirectUriFromAuthorizationEndpointRequest").log("Condition ran but did not log anything");
}

/** upstream: condition/client/AddQueryToRedirectUriInAuthorizationRequest.java */
export function addQueryToRedirectUriInAuthorizationRequest(params: Record<string, unknown>): void {
	const c: Condition = condition("AddQueryToRedirectUriInAuthorizationRequest");
	if (!("redirect_uri" in params)) {
		c.failure("redirect_uri was not found in authorization_endpoint_request");
	}
	const url = new URL(String(params["redirect_uri"]));
	url.searchParams.append("foo", "bar");
	const redirectUri = url.toString();
	delete params["redirect_uri"];
	params["redirect_uri"] = redirectUri;
	c.log("Updated redirect_uri in authorization endpoint request", { redirect_uri: redirectUri });
}

/** upstream: condition/client/ReplaceRedirectUriQueryInAuthorizationRequest.java */
export function replaceRedirectUriQueryInAuthorizationRequest(params: Record<string, unknown>): void {
	const c: Condition = condition("ReplaceRedirectUriQueryInAuthorizationRequest");
	if (!("redirect_uri" in params)) {
		c.failure("redirect_uri was not found in authorization_endpoint_request");
	}
	// UPSTREAM: Spring's DefaultUriBuilderFactory does not normalise the URI; WHATWG URL does (e.g. an empty
	// path of an http(s) URL becomes "/"), so the resulting string can differ slightly for such redirect URIs.
	const url = new URL(String(params["redirect_uri"]));
	url.search = "";
	url.searchParams.append("foo", "bar");
	const redirectUri = url.toString();
	delete params["redirect_uri"];
	params["redirect_uri"] = redirectUri;
	c.log("Updated redirect_uri in authorization endpoint request", { redirect_uri: redirectUri });
}

/**
 * The authorization endpoint answered with the redirect to the redirect_uri although the request was one it must
 * not accept (upstream: AuthorizationEndpointRedirectedBackUnexpectedly).
 */
export function authorizationEndpointRedirectedBackUnexpectedly(): never {
	return condition("AuthorizationEndpointRedirectedBackUnexpectedly").failure(
		"Authorization server redirected back in a case where it should not",
	);
}

/** upstream: condition/client/ExtractAccessTokenFromAuthorizationResponse.java (AbstractExtractAccessToken) */
export function extractAccessTokenFromAuthorizationResponse(response: AuthorizationResponse): AccessToken {
	const c: Condition = condition("ExtractAccessTokenFromAuthorizationResponse");
	const value = str(response.params, "access_token");
	if (!value) {
		c.failure("Couldn't find access token in authorization_endpoint_response");
	}
	const type = str(response.params, "token_type");
	if (!type) {
		c.failure("Couldn't find token type in authorization_endpoint_response");
	}
	const token = { value, type };
	c.success("Extracted the access token", token);
	return token;
}

/**
 * An encrypted id_token in the authorization response must be encrypted to a key the client has (upstream
 * AbstractVerifyJweEncryption).
 *
 * upstream: condition/client/ValidateIdTokenFromAuthorizationResponseEncryption.java
 */
export function validateIdTokenFromAuthorizationResponseEncryption(
	response: AuthorizationResponse,
	clientJwks: unknown,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateIdTokenFromAuthorizationResponseEncryption", ...requirements);
	const idToken = response.params["id_token"];
	if (idToken == null || typeof idToken === "object") {
		c.failure("Couldn't find id_token in authorization_endpoint_response");
	}
	if (verifyJweEncryption(c, String(idToken), clientJwks, "id_token")) {
		c.success("The client has a valid asymmetric key to decrypt the id_token");
	} else {
		c.success("The id_token is not encrypted using an asymmetric encryption algorithm");
	}
}

/**
 * Parses (decrypting with the client's keys if needed) the id_token of the authorization response.
 *
 * upstream: condition/client/ExtractIdTokenFromAuthorizationResponse.java (AbstractExtractJWT)
 */
export async function extractIdTokenFromAuthorizationResponse(
	response: AuthorizationResponse,
	client: RegisteredClient,
	...requirements: string[]
): Promise<ParsedJwt> {
	const c: Condition = condition("ExtractIdTokenFromAuthorizationResponse", ...requirements);
	const key = "authorization_endpoint_response";
	const token = response.params["id_token"];
	if (token == null || typeof token === "object") {
		c.failure("Couldn't find id_token in " + key);
	}
	try {
		const parsed = await parseJwt(String(token), client.client, client.keys?.jwks ?? null);
		if (parsed == null) {
			c.failure("Couldn't parse id_token from " + key + " as a JWT", { id_token: token });
		}
		c.success("Found and parsed the id_token from " + key, { ...parsed });
		return parsed;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse id_token from " + key + " as a JWT", e, { id_token: token });
		}
		if (
			e instanceof JOSEException ||
			(e as Error).name?.startsWith("JOSE") ||
			(e as { code?: string }).code?.startsWith("ERR_J")
		) {
			c.failureFrom("Decrypting id_token from " + key + " failed", e, { id_token: token });
		}
		throw e;
	}
}

/** upstream: condition/client/AddIdTokenEssentialNameClaimToAuthorizationEndpointRequest.java */
export function addIdTokenEssentialNameClaimToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	addClaimToAuthorizationEndpointRequest(
		"AddIdTokenEssentialNameClaimToAuthorizationEndpointRequest",
		params,
		"id_token",
		"name",
		null,
		true,
		requirements,
	);
}

/**
 * A REVIEW entry asking for a screenshot of the error page the OP shows for a request without nonce; see
 * expectSecondLoginPage().
 *
 * upstream: condition/client/ExpectRequestMissingNonceErrorPage.java
 */
export function expectRequestMissingNonceErrorPage(...requirements: string[]): string {
	const placeholder = randomAlphanumeric(10);
	condition("ExpectRequestMissingNonceErrorPage", ...requirements).review(
		"If the server does not return an invalid_request error back to the client, it must show an error page saying the request is invalid as it is missing the 'nonce' claim - upload a screenshot of the error page.",
		{ upload: placeholder },
	);
	return placeholder;
}

/** upstream: condition/client/CheckErrorFromAuthorizationEndpointErrorInvalidRequest.java */
export function checkErrorFromAuthorizationEndpointErrorInvalidRequest(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckErrorFromAuthorizationEndpointErrorInvalidRequest", ...requirements);
	const expected = ["invalid_request"];
	const error = str(response.params, "error");
	if (!error) {
		c.failure("Expected 'error' field not found");
	}
	if (!expected.includes(error)) {
		c.failure("'error' field has unexpected value", { expected, actual: error });
	}
	c.success("Authorization endpoint returned expected error", { expected, actual: error });
}

/**
 * The suite's redirect_uri: `<base url>/callback`, plus the query suffix a module registered for its second client
 * (AddRedirectUriQuerySuffix).
 *
 * upstream: condition/client/CreateRedirectUri.java
 */
export function createRedirectUri(baseUrl: string, suffix: string | null = null, ...requirements: string[]): string {
	const c: Condition = condition("CreateRedirectUri", ...requirements);
	if (baseUrl === "") {
		c.failure("Base URL is empty");
	}
	if (suffix) {
		c.log("Appending suffix to redirect URI", { suffix });
	}
	// calculate the redirect URI based on our given base URL
	const redirectUri = baseUrl + "/callback" + (suffix ?? "");
	c.success("Created redirect URI", { redirect_uri: redirectUri });
	return redirectUri;
}

/** upstream: condition/client/AddRedirectUriQuerySuffix.java */
export function addRedirectUriQuerySuffix(...requirements: string[]): string {
	const redirectUriSuffix = "?dummy1=lorem&dummy2=ipsum";
	condition("AddRedirectUriQuerySuffix", ...requirements).success(
		"Created redirect URI query suffix to test that query sections in the registered redirect url are handled correctly. The redirect url, including this suffix, must be registered for the client as per http://openid.net/certification/fapi_op_testing/",
		{ redirect_uri_suffix: redirectUriSuffix },
	);
	return redirectUriSuffix;
}

/** upstream: condition/client/RedirectQueryTestDisabled.java */
export function redirectQueryTestDisabled(...requirements: string[]): never {
	/* This condition only exists to log a failure */
	return condition("RedirectQueryTestDisabled", ...requirements).failure(
		"Tests that use a redirect uri with a query have been disabled by disableRedirectQueryTest in test configuration",
	);
}

/** upstream: condition/client/SetAuthorizationEndpointRequestResponseTypeToCode.java */
export function setAuthorizationEndpointRequestResponseTypeToCode(params: Record<string, unknown>): void {
	params["response_type"] = "code";
	condition("SetAuthorizationEndpointRequestResponseTypeToCode").success("Added response_type parameter to request", {
		...params,
	});
}

/** upstream: condition/client/SetAuthorizationEndpointRequestResponseModeToJWT.java */
export function setAuthorizationEndpointRequestResponseModeToJWT(params: Record<string, unknown>): void {
	params["response_mode"] = "jwt";
	condition("SetAuthorizationEndpointRequestResponseModeToJWT").success("Added response_mode parameter to request", {
		...params,
	});
}

/** upstream: condition/client/RejectErrorInUrlFragment.java */
export function rejectErrorInUrlFragment(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("RejectErrorInUrlFragment", ...requirements);
	if (str(response.fragment, "error")) {
		c.failure(
			"'error' is present in URL fragment returned from authorization endpoint - it should be returned in the URL query only",
		);
	}
	c.success("'error' is not present in URL fragment returned from authorization endpoint");
}

/** upstream: condition/client/RejectAuthCodeInUrlFragment.java */
export function rejectAuthCodeInUrlFragment(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("RejectAuthCodeInUrlFragment", ...requirements);
	if (str(response.fragment, "code")) {
		c.failure("Authorization code is present in URL fragment returned from authorization endpoint");
	}
	c.success("Authorization code is not present in URL fragment returned from authorization endpoint");
}

/** upstream: condition/client/RejectStateInUrlFragmentForCodeFlow.java */
export function rejectStateInUrlFragmentForCodeFlow(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("RejectStateInUrlFragmentForCodeFlow", ...requirements);
	// UPSTREAM: looks at the code, not the state, in the fragment
	if (str(response.fragment, "code")) {
		c.failure(
			"state is present in URL fragment/hash returned from authorization endpoint - authorization code flow requires it to be returned in the URL query only",
		);
	}
	c.success(
		"state is correctly not present in URL fragment/hash returned from authorization endpoint (as in the authorization code flow it must be returned in the URL query only)",
	);
}

/** upstream: condition/client/AbstractValidateSuccessfulResponseFromAuthorizationEndpoint.java */
function validateSuccessfulResponseFromAuthorizationEndpoint(
	name: string,
	response: AuthorizationResponse,
	expectedParams: string[],
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	const unexpected = Object.fromEntries(Object.entries(response.params).filter(([k]) => !expectedParams.includes(k)));
	if (Object.keys(unexpected).length === 0) {
		c.success("authorization endpoint response does not include unexpected parameters", response.params);
		return;
	}
	c.failure(
		"authorization endpoint response includes unexpected parameters. This may indicate the authorization server has misunderstood the spec, or it may be using extensions the test suite is unaware of.",
		unexpected,
	);
}

/** upstream: condition/client/ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint.java */
export function validateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	// dummy1/2 are returned in the url query for the second client as we require users to register a redirect url
	// that contains an existing url query
	validateSuccessfulResponseFromAuthorizationEndpoint(
		"ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint",
		response,
		["code", "state", "id_token", "session_state", "iss", "dummy1", "dummy2"],
		requirements,
	);
}

/** upstream: condition/client/ValidateSuccessfulJARMResponseFromAuthorizationEndpoint.java */
export function validateSuccessfulJARMResponseFromAuthorizationEndpoint(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	validateSuccessfulResponseFromAuthorizationEndpoint(
		"ValidateSuccessfulJARMResponseFromAuthorizationEndpoint",
		response,
		["code", "state", "session_state", "iss"],
		requirements,
	);
}

/** upstream: condition/client/RequireIssInAuthorizationResponse.java */
export function requireIssInAuthorizationResponse(
	op: Pick<Op, "metadata">,
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("RequireIssInAuthorizationResponse", ...requirements);
	const issuer = op.metadata.issuer;
	const authResponseIssuer = str(response.params, "iss");
	if (authResponseIssuer == null) {
		c.failure("No 'iss' value in authorization response.");
	}
	if (issuer !== authResponseIssuer) {
		c.failure("'iss' parameter in authorization response does not match server's issuer value.", {
			expected: issuer,
			actual: authResponseIssuer,
		});
	}
	c.success("'iss' parameter in authorization response matches server's issuer value.");
}

/** upstream: condition/client/VerifyNoStateInAuthorizationResponse.java */
export function verifyNoStateInAuthorizationResponse(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("VerifyNoStateInAuthorizationResponse", ...requirements);
	if (str(response.params, "state")) {
		c.failure("state has been returned in authorization endpoint response, when it shouldn't have been");
	}
	c.success("Authorization endpoint response is correctly missing 'state'");
}

/** upstream: condition/client/EnsureInvalidRequestError.java */
export function ensureInvalidRequestError(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureInvalidRequestError", ...requirements);
	const error = str(response.params, "error");
	const expected = "invalid_request";
	if (!error) {
		c.failure("Expected 'error' field not found");
	}
	if (error !== expected) {
		c.failure("'error' field has unexpected value", { expected, actual: error });
	}
	c.success("Endpoint returned expected 'error' of '" + expected + "'", { error });
}

/**
 * upstream: condition/client/EnsureInvalidRequestObjectError.java
 * (AbstractEnsureSpecifiedErrorFromAuthorizationEndpointResponse)
 */
export function ensureInvalidRequestObjectError(response: AuthorizationResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureInvalidRequestObjectError", ...requirements);
	const error = str(response.params, "error");
	const expected = "invalid_request_object";
	if (!error) {
		c.failure("Expected 'error' field not found");
	}
	if (error !== expected) {
		c.failure("'error' field has unexpected value", { expected, actual: error });
	}
	c.success("Authorization endpoint returned expected 'error' of '" + expected + "'", { error });
}

/** The shared body of the EnsureInvalidRequest...OrAccessDeniedError conditions below */
function ensurePermittedAuthorizationError(
	name: string,
	response: AuthorizationResponse,
	permitted: string[],
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	const error = str(response.params, "error");
	if (!error) {
		c.failure("Expected 'error' field is missing from authorization endpoint response");
	}
	if (!permitted.includes(error)) {
		c.failure("authorization endpoint response 'error' field has unexpected value", { permitted, actual: error });
	}
	c.success("Authorization endpoint returned an expected 'error'", { permitted, error });
}

/** upstream: condition/client/EnsureInvalidRequestInvalidRequestUriOrAccessDeniedError.java */
export function ensureInvalidRequestInvalidRequestUriOrAccessDeniedError(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	ensurePermittedAuthorizationError(
		"EnsureInvalidRequestInvalidRequestUriOrAccessDeniedError",
		response,
		["invalid_request", "invalid_request_uri", "access_denied"],
		requirements,
	);
}

/** upstream: condition/client/EnsureInvalidRequestInvalidRequestObjectInvalidRequestUriOrAccessDeniedError.java */
export function ensureInvalidRequestInvalidRequestObjectInvalidRequestUriOrAccessDeniedError(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	ensurePermittedAuthorizationError(
		"EnsureInvalidRequestInvalidRequestObjectInvalidRequestUriOrAccessDeniedError",
		response,
		["invalid_request", "invalid_request_object", "invalid_request_uri", "access_denied"],
		requirements,
	);
}

/** A REVIEW placeholder for a screenshot (upstream AbstractCondition.createBrowserInteractionPlaceholder) */
function browserInteractionPlaceholder(name: string, msg: string, requirements: string[]): string {
	const placeholder = randomAlphanumeric(10);
	condition(name, ...requirements).review(msg, { upload: placeholder });
	return placeholder;
}

/** upstream: condition/client/ExpectRequestObjectMissingStateErrorPage.java; returns the placeholder to wait for */
export function expectRequestObjectMissingStateErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectRequestObjectMissingStateErrorPage",
		"If the server does not return an invalid_request_object error back to the client, it must show an error page saying the request object is invalid as it is missing the 'state' claim - upload a screenshot of the error page.",
		requirements,
	);
}

/** upstream: condition/client/ExpectPkceMissingErrorPage.java; returns the placeholder to wait for */
export function expectPkceMissingErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectPkceMissingErrorPage",
		"Show an error page saying PKCE / code_challenge / code_challenge_method are missing from the request.",
		requirements,
	);
}

/** upstream: condition/client/ExpectRequestObjectMissingExpClaimErrorPage.java; returns the placeholder to wait for */
export function expectRequestObjectMissingExpClaimErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectRequestObjectMissingExpClaimErrorPage",
		"If the server does not return an invalid_request_object error back to the client, it must show an error page saying the request object is invalid as it is missing the 'exp' claim - upload a screenshot of the error page.",
		requirements,
	);
}

/** upstream: condition/client/ExpectExpiredRequestObjectClaimErrorPage.java; returns the placeholder to wait for */
export function expectExpiredRequestObjectClaimErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectExpiredRequestObjectClaimErrorPage",
		"If the server does not return an invalid_request_object error back to the client, it must show an error page saying the request object is invalid as it is using the expired 'exp' value claim - upload a screenshot of the error page.",
		requirements,
	);
}

/**
 * The user pressed 'cancel' on the login screen or denied consent: the error must be access_denied.
 *
 * upstream: condition/client/ExpectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest.java
 * (AbstractExpectAccessDeniedErrorDueToUserRejectingRequest)
 */
export function expectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition(
		"ExpectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest",
		...requirements,
	);
	const callbackParams = response.params;
	if (!("error" in callbackParams)) {
		c.failure(
			"error parameter not found. When running this test, the tester MUST press 'cancel' on the login screen or deny consent so that an error is returned to the relying party.",
			callbackParams,
		);
	}
	const error = getString(callbackParams["error"]);
	if (!error) {
		c.failure(
			"error parameter empty/invalid. When running this test, the tester MUST press 'cancel' on the login screen or deny consent so that an error is returned to the relying party.",
			callbackParams,
		);
	}
	const expected = "access_denied";
	if (error !== expected) {
		c.failure(
			"error value is incorrect. When running this test, the tester MUST press 'cancel' on the login screen or deny consent so that an error is returned to the relying party.",
			{ expected, actual: error },
		);
	}
	c.success("error parameter is correctly '" + error + "'");
}

/** upstream: condition/client/ExpectRequestObjectWithLongNonceErrorPage.java; returns the placeholder to wait for */
export function expectRequestObjectWithLongNonceErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectRequestObjectWithLongNonceErrorPage",
		"If the server does not return an invalid_request error back to the client, it must show an error page (saying server rejects long nonce at authorization endpoint - upload a screenshot of the error page) or must successfully authenticate and return the nonce correctly.",
		requirements,
	);
}

/** upstream: condition/client/ExpectRequestObjectWithLongStateErrorPage.java; returns the placeholder to wait for */
export function expectRequestObjectWithLongStateErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectRequestObjectWithLongStateErrorPage",
		"If the server does not return an invalid_request error back to the client, it must show an error page (saying server rejects long state at authorization endpoint - upload a screenshot of the error page) or must successfully authenticate and return the state correctly.",
		requirements,
	);
}

/** upstream: condition/client/WarningAboutRejectingLongState.java */
export function warningAboutRejectingLongState(...requirements: string[]): never {
	return condition("WarningAboutRejectingLongState", ...requirements).failure(
		"Rejecting a state of this length may result in interoperability issues.",
	);
}

/** upstream: condition/client/ExpectAuthorizationRequestWithoutRequestObjectErrorPage.java; returns the placeholder to wait for */
export function expectAuthorizationRequestWithoutRequestObjectErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectAuthorizationRequestWithoutRequestObjectErrorPage",
		"If the server does not return an invalid_request error back to the client, it must show an error page saying the request is invalid as it is missing the request_object - upload a screenshot of the error page.",
		requirements,
	);
}

/** upstream: condition/common/ExpectResponseTypeErrorPage.java; returns the placeholder to wait for */
export function expectResponseTypeErrorPage(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectResponseTypeErrorPage",
		"If the server does not return an error back to the client, " +
			"upload a screenshot of the error page showing an invalid response type error.",
		requirements,
	);
}

/** upstream: condition/client/SetAuthorizationEndpointRequestResponseTypeToCodeIdtoken.java */
export function setAuthorizationEndpointRequestResponseTypeToCodeIdtoken(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["response_type"] = "code id_token";
	condition("SetAuthorizationEndpointRequestResponseTypeToCodeIdtoken", ...requirements).success(
		"Added response_type parameter to request",
		{ ...params },
	);
}

/** upstream: condition/client/SetAuthorizationEndpointRequestResponseTypeToToken.java */
export function setAuthorizationEndpointRequestResponseTypeToToken(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	params["response_type"] = "token";
	condition("SetAuthorizationEndpointRequestResponseTypeToToken", ...requirements).success(
		"Added response_type parameter to request",
		{ ...params },
	);
}

/**
 * It doesn't really matter if the error in the fragment or the query, the specs aren't entirely clear on the
 * matter: whichever carries `error` becomes the authorization endpoint response (`response.params`).
 *
 * upstream: condition/client/DetectWhetherErrorResponseIsInQueryOrFragment.java
 */
export function detectWhetherErrorResponseIsInQueryOrFragment(response: AuthorizationResponse): void {
	const c: Condition = condition("DetectWhetherErrorResponseIsInQueryOrFragment");
	if ("error" in response.query) {
		c.log("Server has chosen to return 'error' in URL query, using query as response", {
			error: str(response.query, "error"),
		});
		response.params = response.query;
		return;
	}
	if ("error" in response.fragment) {
		c.log("Server has chosen to return 'error' in URL fragment, using fragment as the response", {
			error: str(response.fragment, "error"),
		});
		response.params = response.fragment;
		return;
	}
	c.failure("authorization server did not return an error in the url query or fragment");
}

/**
 * Check to make sure a "unsupported_response_type" or "invalid_request" error was received from the server
 *
 * upstream: condition/client/EnsureUnsupportedResponseTypeOrInvalidRequestError.java
 */
export function ensureUnsupportedResponseTypeOrInvalidRequestError(
	response: AuthorizationResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureUnsupportedResponseTypeOrInvalidRequestError", ...requirements);
	const permitted = ["invalid_request", "unsupported_response_type"];
	const error = str(response.params, "error");
	if (!error) {
		c.failure("Expected 'error' field is missing from authorization endpoint response");
	}
	if (!permitted.includes(error)) {
		c.failure("authorization endpoint response 'error' field has unexpected value", { permitted, actual: error });
	}
	c.success("Authorization endpoint returned an expected 'error'", { permitted, error });
}

/**
 * The standard claims of OIDCC 5.1, as per https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
 * (upstream AddAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims.oidcClaims)
 */
export const OIDC_STANDARD_CLAIMS = [
	"sub",
	"name",
	"given_name",
	"family_name",
	"middle_name",
	"nickname",
	"preferred_username",
	"profile",
	"picture",
	"website",
	"email",
	"email_verified",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"phone_number",
	"phone_number_verified",
	"address",
	"updated_at",
];

/**
 * Whether `claims_supported` of the server metadata lists any of the standard OpenID Connect claims (upstream env
 * "at_least_one_oidc_standard_claim_supported").
 *
 * upstream: condition/client/CheckIfOidcStandardClaimsSupported.java
 */
export function checkIfOidcStandardClaimsSupported(metadata: ServerMetadata, ...requirements: string[]): boolean {
	const c: Condition = condition("CheckIfOidcStandardClaimsSupported", ...requirements);
	const key = "claims_supported";
	const claimsSupportedEl = metadata[key];
	if (claimsSupportedEl === undefined) {
		c.log(key + " not found in server metadata");
		return false;
	}
	if (!Array.isArray(claimsSupportedEl)) {
		c.failure(key + " in server metadata is not an array", { [key]: claimsSupportedEl });
	}
	// a HashSet: the claims in java.util.HashMap's order
	const claimsSupported = new JavaHashMap();
	for (const el of claimsSupportedEl) {
		if (typeof el !== "string") {
			c.failure(key + " in server metadata is not an array", { [key]: claimsSupportedEl });
		}
		claimsSupported.put(el, null);
	}
	const standard = claimsSupported
		.entries()
		.map(([claim]) => claim)
		.filter((claim) => OIDC_STANDARD_CLAIMS.includes(claim));
	if (standard.length === 0) {
		c.log(key + " in server metadata does not contain any of the OpenID Connect standard claims");
		return false;
	}
	c.log(key + " in server metadata contains at least one OpenID Connect standard claims", {
		standard_claims: standard,
	});
	return true;
}

/**
 * The `claims` request parameter's object for `location` (id_token, userinfo, ...), created as needed.
 *
 * upstream: condition/client/AbstractAddClaimToAuthorizationEndpointRequest.getClaimsForLocation
 */
function claimsForLocation(c: Condition, params: Record<string, unknown>, location: string): Record<string, unknown> {
	let claims: Record<string, unknown>;
	if ("claims" in params) {
		const existing = params["claims"];
		if (!isObject(existing)) {
			c.failure("Invalid claims entry in authorization_endpoint_request", { authorization_endpoint_request: params });
		}
		claims = existing;
	} else {
		claims = {};
		params["claims"] = claims;
	}
	if (location in claims) {
		const existing = claims[location];
		if (!isObject(existing)) {
			c.failure("Invalid " + location + " entry in authorization_endpoint_request", {
				authorization_endpoint_request: params,
			});
		}
		return existing;
	}
	const forLocation = {};
	claims[location] = forLocation;
	return forLocation;
}

/**
 * Requests each claim in a different form (null, an empty object, essential, an unknown member, not essential),
 * cycling through them; we test (if we have enough supported claims!) all the ways a claim can be requested as per
 * https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests. We don't test value / values as
 * we don't know what values the server may return.
 *
 * upstream: condition/client/AbstractAddClaimToAuthorizationEndpointRequest.addRequestsForClaims
 */
function addRequestsForClaims(claimsObject: Record<string, unknown>, claimsToAdd: string[]): void {
	const requestTypes = ["AsNull", "AsEmpty", "EssentialTrue", "Random", "EssentialFalse"] as const;
	let requestType = 0;
	for (const claimName of claimsToAdd) {
		switch (requestTypes[requestType]) {
			case "AsNull":
				claimsObject[claimName] = null;
				break;
			case "AsEmpty":
				claimsObject[claimName] = {};
				break;
			case "EssentialTrue":
				claimsObject[claimName] = { essential: true };
				break;
			case "Random":
				// "Other members MAY be defined to provide additional information about the requested Claims. Any members used that are not understood MUST be ignored."
				claimsObject[claimName] = { [randomAlphanumeric(10)]: randomAlphanumeric(10) };
				break;
			case "EssentialFalse":
				claimsObject[claimName] = { essential: false };
				break;
		}
		requestType = (requestType + 1) % requestTypes.length;
	}
}

/**
 * Requests every standard claim of `claims_supported` in the id_token and at the userinfo endpoint.
 *
 * upstream: condition/client/AddAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims.java
 */
export function addAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims(
	params: Record<string, unknown>,
	metadata: ServerMetadata,
	...requirements: string[]
): void {
	const c: Condition = condition(
		"AddAllSupportedStandardClaimsToAuthorizationEndpointRequestIdTokenAndUserinfoClaims",
		...requirements,
	);
	const nonOidcClaims: string[] = [];
	const supportedOidcClaims: string[] = [];
	const serverValues = metadata["claims_supported"];
	if (!Array.isArray(serverValues)) {
		// UPSTREAM: getAsJsonArray() on a missing or non-array claims_supported throws
		throw new TypeError("claims_supported is not a JSON array");
	}
	for (const el of serverValues) {
		const claimName = getString(el);
		if (!OIDC_STANDARD_CLAIMS.includes(claimName)) {
			nonOidcClaims.push(claimName);
			continue;
		}
		supportedOidcClaims.push(claimName);
	}
	if (supportedOidcClaims.length === 0) {
		c.failure("Server does not seem to support any standard OpenID Connect claims.", {
			oidc_claims: OIDC_STANDARD_CLAIMS,
			supported_claims: serverValues,
		});
	}
	for (const location of ["id_token", "userinfo"]) {
		addRequestsForClaims(claimsForLocation(c, params, location), supportedOidcClaims);
	}
	c.success(
		"Added OpenID Connect claims from claims_supported to authorization_endpoint_request for id_token and userinfo using various different forms of request",
		{ authorization_endpoint_request: params, oidc_claims: OIDC_STANDARD_CLAIMS, non_oidc_claims: nonOidcClaims },
	);
}

/**
 * Requests a random claim in a random location of the `claims` parameter, which the server must ignore.
 *
 * upstream: condition/client/AddRandomLocationClaimsToAuthorizationEndpointRequest.java
 */
export function addRandomLocationClaimsToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("AddRandomLocationClaimsToAuthorizationEndpointRequest", ...requirements);
	const location = randomAlphanumeric(10);
	addRequestsForClaims(claimsForLocation(c, params, location), [randomAlphanumeric(10)]);
	c.success(
		"Added a request for claims to be returned in a random location to the authorization_endpoint_request. As per spec, 'Any members used that are not understood MUST be ignored.'.",
		{ authorization_endpoint_request: params },
	);
}
