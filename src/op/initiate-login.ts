/**
 * Third-party-initiated login (OpenID Connect Core 4, Dynamic Client Registration 2): the client registers an
 * `initiate_login_uri`, which the OP must keep in the registration and the client configuration.
 *
 *   const client = await configureClient((request) => {
 *     initiateLoginUri = initiateLogin.createInitiateLoginUri(op.baseUrl, "OIDCC-4", "OIDCR-2");
 *     initiateLogin.addInitiateLoginUriToDynamicRegistrationRequest(request, initiateLoginUri, "OIDCC-4", "OIDCR-2");
 *   });
 *   soft(() => initiateLogin.validateInitiateLoginUriInRegistrationResponse(client.client, initiateLoginUri, "OIDCR-3.2"));
 */
import { condition, type Condition } from "../suite/conditions.ts";
import type { EndpointResponse } from "../suite/http.ts";
import type { Client } from "./registration.ts";

/**
 * upstream: condition/client/CreateInitiateLoginUri.java (upstream's external_url_override is the server's externalUrl
 * here, already part of `baseUrl`)
 */
export function createInitiateLoginUri(baseUrl: string, ...requirements: string[]): string {
	const c: Condition = condition("CreateInitiateLoginUri", ...requirements);
	if (baseUrl.length === 0) {
		c.failure("Base URL is empty");
	}
	// this url is never called: it is only sent in the registration request
	const uri = baseUrl + "/initiate_login";
	c.success("Created initiate_login URI", { initiate_login_uri: uri });
	return uri;
}

/** upstream: condition/client/AddInitiateLoginUriToDynamicRegistrationRequest.java */
export function addInitiateLoginUriToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	initiateLoginUri: string,
	...requirements: string[]
): void {
	registrationRequest["initiate_login_uri"] = initiateLoginUri;
	condition("AddInitiateLoginUriToDynamicRegistrationRequest", ...requirements).log(
		"Added initiate_login_uri to dynamic registration request",
		{ dynamic_registration_request: registrationRequest },
	);
}

/** upstream: condition/client/AddInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest.java */
export function addInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	initiateLoginUri: string,
	...requirements: string[]
): void {
	const uri = initiateLoginUri.replaceAll("https://", "http://");
	registrationRequest["initiate_login_uri"] = uri;
	condition("AddInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest", ...requirements).log(
		"Added non-https version of initiate_login_uri to dynamic registration request",
		{ initiate_login_uri: uri },
	);
}

/** upstream: condition/client/ValidateInitiateLoginUriInRegistrationResponse.java */
export function validateInitiateLoginUriInRegistrationResponse(
	client: Client,
	initiateLoginUri: string,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateInitiateLoginUriInRegistrationResponse", ...requirements);
	const returned = client["initiate_login_uri"];
	if (returned == null) {
		c.failure("initiate_login_uri missing from client registration response.");
	}
	if (returned !== initiateLoginUri) {
		c.failure("initiate_login_uri in client registration response does not match the value in the request.", {
			requested: initiateLoginUri,
			actual: returned,
		});
	}
	c.success("initiate_login_uri in registration response is correct.", { actual: returned });
}

/** upstream: condition/client/ValidateInitiateLoginUriInConfigurationResponse.java */
export function validateInitiateLoginUriInConfigurationResponse(
	response: EndpointResponse,
	initiateLoginUri: string,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateInitiateLoginUriInConfigurationResponse", ...requirements);
	const returned = (response.body_json as Record<string, unknown> | undefined)?.["initiate_login_uri"];
	if (returned == null) {
		c.failure("initiate_login_uri missing from client configuration response.");
	}
	if (returned !== initiateLoginUri) {
		c.failure("initiate_login_uri in client configuration response does not match the value the client registered.", {
			requested: initiateLoginUri,
			actual: returned,
		});
	}
	c.success("initiate_login_uri in configuration response is correct.", { actual: returned });
}
