/**
 * Checks that apply to the response of any endpoint (status, content type) and to the error fields of any OAuth
 * error response (authorization endpoint, token endpoint, ...). The `responseName` / `endpointName` arguments are
 * the names upstream weaves into the messages ("token_endpoint_response", "dynamic registration", ...).
 */
import { condition, type Condition } from "../suite/conditions.ts";
import type { EndpointResponse } from "../suite/http.ts";

/** upstream: condition/client/AbstractEnsureHttpStatusCode.java */
function ensureHttpStatusCode(name: string, res: EndpointResponse, expected: number, ...requirements: string[]): void {
	const c: Condition = condition(name, ...requirements);
	if (res.status !== expected) {
		c.failure(res.endpoint_name + " endpoint returned an unexpected http status", {
			http_status: res.status,
			expected_status: expected,
		});
	}
	c.success(res.endpoint_name + " endpoint returned the expected http status", {
		http_status: res.status,
		expected_status: expected,
	});
}

/** upstream: condition/client/EnsureHttpStatusCodeIs200.java */
export function ensureHttpStatusCodeIs200(res: EndpointResponse, ...requirements: string[]): void {
	ensureHttpStatusCode("EnsureHttpStatusCodeIs200", res, 200, ...requirements);
}

/** upstream: condition/client/EnsureHttpStatusCodeIs201.java */
export function ensureHttpStatusCodeIs201(res: EndpointResponse, ...requirements: string[]): void {
	ensureHttpStatusCode("EnsureHttpStatusCodeIs201", res, 201, ...requirements);
}

/**
 * upstream: condition/client/AbstractCheckEndpointContentTypeReturned.java. `where` is the environment key
 * upstream names in the message ("endpoint_response", "token_endpoint_response_headers").
 */
export function checkContentType(
	name: string,
	where: string,
	contentType: unknown,
	expected: string,
	...requirements: string[]
): void {
	const c: Condition = condition(name, ...requirements);
	if (typeof contentType !== "string" || contentType === "") {
		c.failure("Couldn't find content-type header in " + where);
	}
	const mimeType = contentType.split(";")[0].trim();
	if (mimeType !== expected) {
		c.failure("Invalid content-type header in " + where, { expected, actual: contentType });
	}
	c.success(where + " Content-Type: header is " + expected);
}

/** upstream: condition/client/EnsureContentTypeJson.java (on the response mapped to "endpoint_response") */
export function ensureContentTypeJson(res: EndpointResponse, ...requirements: string[]): void {
	checkContentType(
		"EnsureContentTypeJson",
		"endpoint_response",
		res.headers["content-type"],
		"application/json",
		...requirements,
	);
}

/** An OAuth error response: the authorization response parameters or a token endpoint JSON body */
export type ErrorResponse = Record<string, unknown>;

function stringField(response: ErrorResponse, key: string): string | null {
	const v = response[key];
	return typeof v === "string" ? v : null;
}

/** upstream: condition/client/AbstractCheckErrorDescriptionContainsCRLFTAB.java */
export function checkErrorDescriptionContainsCRLFTAB(
	name: string,
	responseName: string,
	response: ErrorResponse,
	...requirements: string[]
): void {
	const c: Condition = condition(name, ...requirements);
	const errorDescription = stringField(response, "error_description");
	if (!errorDescription) {
		c.success(responseName + " did not include optional 'error_description' field");
		return;
	}
	if (/[\n\r\t]/.test(errorDescription)) {
		c.failure("'error_description' field includes characters CR, LF or TAB, these are not recommended to include", {
			error_description: errorDescription,
			see: "https://bitbucket.org/openid/connect/issues/1147/certification-rfc6749-must-for",
		});
	}
	c.success(responseName + " 'error_description' field does not include CR/LF/TAB", {
		error_description: errorDescription,
	});
}

/** upstream: condition/client/AbstractValidateErrorDescriptionFromResponseError.java */
export function validateErrorDescription(
	name: string,
	responseName: string,
	response: ErrorResponse,
	...requirements: string[]
): void {
	const c: Condition = condition(name, ...requirements);
	const errorDescription = stringField(response, "error_description");
	if (!errorDescription) {
		c.success(responseName + " did not include optional 'error_description' field");
		return;
	}
	// oxlint-disable-next-line no-control-regex -- RFC6749 allows tab, LF and CR in error_description
	if (!/^(?:[\x09\x0A\x0D\x20-\x21\x23-\x5B\x5D-\x7E]+)$/.test(errorDescription)) {
		c.failure(
			"'error_description' field MUST NOT include characters outside the set %09-0A (Tab and LF) / %x0D (CR) / %x20-21 / %x23-5B / %x5D-7E",
			{ error_description: errorDescription },
		);
	}
	c.success(responseName + " error returned valid 'error_description' field", { error_description: errorDescription });
}

/** upstream: condition/client/AbstractValidateErrorUriFromResponseError.java */
export function validateErrorUri(
	name: string,
	responseName: string,
	response: ErrorResponse,
	...requirements: string[]
): void {
	const c: Condition = condition(name, ...requirements);
	const errorUri = stringField(response, "error_uri");
	if (!errorUri) {
		c.success(responseName + " did not include optional 'error_uri' field");
		return;
	}
	// UPSTREAM: Java uses URI.create(errorUri).toURL() (rejects relative references and schemes without a URL handler)
	if (!URL.canParse(errorUri)) {
		c.failure("'error_uri' field MUST conform to the URI-reference syntax", { error_uri: errorUri });
	}
	if (!/^(?:[\x21\x23-\x5B\x5D-\x7E]+)$/.test(errorUri)) {
		c.failure("'error_uri' field MUST NOT include characters outside the set %x21 / %x23-5B / %x5D-7E", {
			error_uri: errorUri,
		});
	}
	c.success(responseName + " returned valid 'error_uri' field", { error_uri: errorUri });
}

/** upstream: condition/client/EnsureHttpStatusCodeIs400.java */
export function ensureHttpStatusCodeIs400(res: EndpointResponse, ...requirements: string[]): void {
	ensureHttpStatusCode("EnsureHttpStatusCodeIs400", res, 400, ...requirements);
}

/** upstream: condition/client/EnsureHttpStatusCodeIs4xx.java */
export function ensureHttpStatusCodeIs4xx(res: EndpointResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureHttpStatusCodeIs4xx", ...requirements);
	if (res.status == null) {
		c.failure("Http status can not be null.");
	}
	if (res.status >= 400 && res.status <= 499) {
		c.success(res.endpoint_name + " endpoint http status code was " + res.status);
		return;
	}
	c.failure(res.endpoint_name + " endpoint returned a different http status than expected", {
		actual: res.status,
		expected: "400 to 499",
	});
}

/** upstream: condition/client/EnsureHttpStatusCodeIs200or201.java */
export function ensureHttpStatusCodeIs200or201(res: EndpointResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureHttpStatusCodeIs200or201", ...requirements);
	if (res.status == null) {
		c.failure("Http status can not be null.");
	}
	if (res.status >= 200 && res.status <= 201) {
		c.success(res.endpoint_name + " endpoint http status code was " + res.status);
		return;
	}
	c.failure(res.endpoint_name + " endpoint returned a different http status than expected", {
		actual: res.status,
		expected: "200 or 201",
	});
}

/** upstream: condition/client/EnsureHttpStatusCodeIs400or401.java */
export function ensureHttpStatusCodeIs400or401(res: EndpointResponse, ...requirements: string[]): void {
	const c: Condition = condition("EnsureHttpStatusCodeIs400or401", ...requirements);
	if (res.status == null) {
		c.failure("Http status can not be null.");
	}
	if (res.status !== 400 && res.status !== 401) {
		c.failure(res.endpoint_name + " endpoint returned a different http status than expected", {
			actual: res.status,
			expected: "400 or 401",
		});
	}
	c.success(res.endpoint_name + " endpoint http status code was " + res.status);
}

/** upstream: condition/client/EnsureContentTypeApplicationJwt.java */
export function ensureContentTypeApplicationJwt(res: EndpointResponse, ...requirements: string[]): void {
	checkContentType(
		"EnsureContentTypeApplicationJwt",
		"endpoint_response",
		res.headers["content-type"],
		"application/jwt",
		...requirements,
	);
}
