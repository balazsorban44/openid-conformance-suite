/**
 * The client the suite uses against the OP: dynamically registered (OpenID Connect Dynamic Client Registration)
 * or taken from the test configuration, and unregistered after the test.
 */
import { calculateJwkThumbprint } from "jose";
import { condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import { endpointResponse, HttpError, jsonBody, request, type EndpointResponse } from "../suite/http.ts";
import { generateRsaJwk, privateJwks, publicJwks, type Jwks } from "../suite/jose.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import { findStructurallyInvalidKeys, issuesToJson, parseJWK, parseJWKSet } from "../suite/jose-jwk.ts";
import { ParseException } from "../suite/errors.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { Op } from "./op.ts";
import { ensureContentTypeJson, ensureHttpStatusCodeIs201 } from "./endpoint.ts";
import { checkDistinctKeyIdValueInClientJWKs } from "./jwks.ts";

/** upstream AbstractCondition: where the suite asks to be contacted */
export const SUPPORT_EMAIL = "certification@oidf.org";

/**
 * The client (upstream env "client": the configured client object, or the registration response) plus the
 * client's private keys (upstream env "client_jwks"), when it has any.
 */
export interface Client {
	client_id: string;
	client_secret?: string;
	scope?: string;
	registration_access_token?: string;
	registration_client_uri?: string;
	[key: string]: unknown;
}

export interface ClientKeys {
	/** The private JWK set (upstream "client_jwks") */
	jwks: Jwks;
	/** The public JWK set (upstream "client_public_jwks") */
	publicJwks: Jwks;
}

export interface RegisteredClient {
	client: Client;
	/** null for a static client configured without `jwks` */
	keys: ClientKeys | null;
	/** True when the suite registered the client (and must unregister it) */
	dynamic: boolean;
	/** The registration request the suite sent (upstream env "dynamic_registration_request"), for a dynamic client */
	registrationRequest?: Record<string, unknown>;
}

/** upstream: condition/client/StoreOriginalClientConfiguration.java */
export function storeOriginalClientConfiguration(config: TestConfig, key = "client"): Record<string, unknown> {
	const c: Condition = condition(
		key === "client2" ? "StoreOriginalClient2Configuration" : "StoreOriginalClientConfiguration",
	);
	const template = config[key];
	if (template == null || typeof template !== "object" || Array.isArray(template)) {
		c.log("No client details on configuration, created an empty original_client_config object.");
		return {};
	}
	c.log("Created original_client_config object from the client configuration.", template as Record<string, unknown>);
	return template as Record<string, unknown>;
}

/** upstream: condition/client/ExtractClientNameFromStoredConfig.java */
export function extractClientNameFromStoredConfig(original: Record<string, unknown>): string | null {
	const name = typeof original["client_name"] === "string" && original["client_name"] ? original["client_name"] : null;
	condition("ExtractClientNameFromStoredConfig").log("Extracted client_name from stored client configuration.", {
		client_name: name,
	});
	return name;
}

/** upstream: condition/client/ExtractInitialAccessTokenFromStoredConfig.java */
export function extractInitialAccessTokenFromStoredConfig(original: Record<string, unknown>): string | null {
	const token =
		typeof original["initial_access_token"] === "string" && original["initial_access_token"]
			? original["initial_access_token"]
			: null;
	condition("ExtractInitialAccessTokenFromStoredConfig").log(
		"Extracted initial access_token from stored client configuration.",
		{
			initial_access_token: token,
		},
	);
	return token;
}

/** upstream: condition/client/GenerateRS256ClientJWKs.java (AbstractGenerateClientJWKs.publishClientJWKs) */
export function generateRS256ClientJWKs(): ClientKeys {
	const key = generateRsaJwk("RS256", "sig");
	const jwks = privateJwks({ keys: [key] });
	const pub = publicJwks({ keys: [key] });
	condition("GenerateRS256ClientJWKs").success("Generated client JWKs", { client_jwks: jwks, public_client_jwks: pub });
	return { jwks, publicJwks: pub };
}

export interface RegistrationRequestOptions {
	/** config client.client_name (the test id is appended) */
	clientName: string | null;
	/** the variant's response_type ("code", "id_token", "code id_token", ...) */
	responseType: string;
	/** the variant's client_auth_type, registered as token_endpoint_auth_method */
	clientAuthType: string;
	redirectUri: string;
	publicJwks: Jwks;
	/**
	 * Register the keys by reference instead of by value: upstream's modules replace AddPublicJwksToDynamicRegistrationRequest
	 * with AddJwksUriToDynamicRegistrationRequest (the suite serves the keys at this URL)
	 */
	jwksUri?: string;
	/** What the module adds to the request after the OIDCC defaults (upstream createDynamicClientRegistrationRequest overrides) */
	customize?: (registrationRequest: Record<string, unknown>) => void;
}

/**
 * The registration request of the OIDCC tests: client_name, grant_types for the response type, the public keys,
 * token_endpoint_auth_method, response_types, redirect_uris, contacts.
 *
 * upstream: sequence/client/OIDCCCreateDynamicClientRegistrationRequest.java (after GenerateRS256ClientJWKs) with
 * condition/client/CreateEmptyDynamicRegistrationRequest.java, AddClientNameToDynamicRegistrationRequest.java,
 * AddAuthorizationCodeGrantTypeToDynamicRegistrationRequest.java, AddImplicitGrantTypeToDynamicRegistrationRequest.java,
 * AddPublicJwksToDynamicRegistrationRequest.java, AddTokenEndpointAuthMethodToDynamicRegistrationRequestFromEnvironment.java,
 * AddResponseTypesArrayToDynamicRegistrationRequestFromEnvironment.java, AddRedirectUriToDynamicRegistrationRequest.java,
 * AddContactsToDynamicRegistrationRequest.java
 */
export function createDynamicRegistrationRequest(
	testId: string,
	opts: RegistrationRequestOptions,
): Record<string, unknown> {
	const req: Record<string, unknown> = {};
	condition("CreateEmptyDynamicRegistrationRequest").log("Created empty dynamic registration request");

	req["client_name"] = opts.clientName ? opts.clientName + " " + testId : "OIDF Conformance Test " + testId;
	condition("AddClientNameToDynamicRegistrationRequest").log("Added client_name to registration request", { ...req });

	const responseTypes = opts.responseType.split(" ");
	const addGrantType = (name: string, grantType: string) => {
		const grantTypes = [...((req["grant_types"] as string[] | undefined) ?? []), grantType];
		req["grant_types"] = grantTypes;
		condition(name).log(`Added '${grantType}' to 'grant_types'`, { grant_types: grantTypes });
	};
	if (responseTypes.includes("code")) {
		addGrantType("AddAuthorizationCodeGrantTypeToDynamicRegistrationRequest", "authorization_code");
	}
	if (responseTypes.includes("id_token") || responseTypes.includes("token")) {
		addGrantType("AddImplicitGrantTypeToDynamicRegistrationRequest", "implicit");
	}

	if (opts.jwksUri != null) {
		req["jwks_uri"] = opts.jwksUri;
		condition("AddJwksUriToDynamicRegistrationRequest").log("Added jwks_uri to dynamic registration request", {
			dynamic_registration_request: req,
		});
	} else {
		req["jwks"] = opts.publicJwks;
		condition("AddPublicJwksToDynamicRegistrationRequest", "RFC7591-2").log(
			"Added client public JWKS to dynamic registration request",
			{
				dynamic_registration_request: req,
			},
		);
	}

	req["token_endpoint_auth_method"] = opts.clientAuthType;
	condition("AddTokenEndpointAuthMethodToDynamicRegistrationRequestFromEnvironment").log(
		"Added token endpoint auth method to dynamic registration request",
		{ dynamic_registration_request: req },
	);

	req["response_types"] = [opts.responseType];
	condition("AddResponseTypesArrayToDynamicRegistrationRequestFromEnvironment").log(
		"Added response_types array to dynamic registration request",
		{ dynamic_registration_request: req },
	);

	req["redirect_uris"] = [opts.redirectUri];
	condition("AddRedirectUriToDynamicRegistrationRequest").log(
		"Added redirect_uris array to dynamic registration request",
		{
			dynamic_registration_request: req,
		},
	);

	req["contacts"] = [SUPPORT_EMAIL];
	condition("AddContactsToDynamicRegistrationRequest").log("Added contacts array to dynamic registration request", {
		dynamic_registration_request: req,
	});
	opts.customize?.(req);
	return req;
}

/** upstream: condition/client/CallDynamicRegistrationEndpoint.java */
export async function callDynamicRegistrationEndpoint(
	metadata: ServerMetadata,
	registrationRequest: Record<string, unknown>,
	initialAccessToken: string | null,
	...requirements: string[]
): Promise<EndpointResponse> {
	const c: Condition = condition("CallDynamicRegistrationEndpoint", ...requirements);
	const endpoint = metadata.registration_endpoint;
	if (endpoint == null) {
		c.failure("Couldn't find registration endpoint");
	}
	const headers: Record<string, string> = {
		Accept: "application/json",
		"Accept-Charset": "utf-8",
		"Content-Type": "application/json",
	};
	// https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration
	if (initialAccessToken) {
		headers["Authorization"] = "Bearer " + initialAccessToken;
	}
	let res;
	try {
		res = await request(c.name, { url: endpoint, method: "POST", headers, body: JSON.stringify(registrationRequest) });
	} catch (e) {
		if (e instanceof HttpError) {
			c.failureFrom("Call to registration endpoint failed - " + e.message, e);
		}
		throw e;
	}
	const response = endpointResponse("dynamic registration", res);
	if (!res.body) {
		c.failure("Empty response from the dynamic registration endpoint");
	}
	if (response.body_json === undefined) {
		c.failure("Response from dynamic registration endpoint does not appear to be JSON.", { response: res.body });
	}
	c.log("Parsed registration endpoint response", { ...response });
	return response;
}

/** upstream: condition/client/CheckNoErrorFromDynamicRegistrationEndpoint.java */
export function checkNoErrorFromDynamicRegistrationEndpoint(
	response: EndpointResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckNoErrorFromDynamicRegistrationEndpoint", ...requirements);
	if ((response.body_json as Record<string, unknown> | undefined)?.["error"] != null) {
		c.failure("'error' field found in response from dynamic registration endpoint.", { ...response });
	}
	c.success("Dynamic registration endpoint did not return an error.");
}

/** upstream: condition/client/ExtractDynamicRegistrationResponse.java */
export function extractDynamicRegistrationResponse(response: EndpointResponse, ...requirements: string[]): Client {
	const c: Condition = condition("ExtractDynamicRegistrationResponse", ...requirements);
	const client = response.body_json as Record<string, unknown> | undefined;
	if (client == null) {
		c.failure("No json response from dynamic registration endpoint");
	}
	if (client["client_id"] === undefined) {
		c.failure("no client id in dynamic registration response");
	}
	c.success("Extracted client from dynamic registration response", { client_id: client["client_id"] });
	return structuredClone(client) as Client;
}

/** upstream: condition/client/VerifyClientManagementCredentials.java (AbstractJsonUriIsValidAndHttps) */
export function verifyClientManagementCredentials(client: Client, ...requirements: string[]): void {
	const c: Condition = condition("VerifyClientManagementCredentials", ...requirements);
	const hasUri = "registration_client_uri" in client;
	const hasToken = "registration_access_token" in client;
	if (!hasUri && !hasToken) {
		c.log("Dynamic registration returned neither registration_client_uri nor registration_access_token");
		return;
	}
	if (!hasUri) {
		c.failure("Dynamic registration returned registration_access_token but not registration_client_uri");
	}
	if (!hasToken) {
		c.failure("Dynamic registration returned registration_client_uri but not registration_access_token");
	}
	// AbstractJsonUriIsValidAndHttps
	const uri = String(client.registration_client_uri);
	const token = String(client.registration_access_token);
	if (!uri) {
		c.failure("registration_client_uri must not be an empty string");
	}
	if (!URL.canParse(uri)) {
		c.failure("Invalid URL. Unable to parse.");
	}
	if (new URL(uri).protocol !== "https:") {
		c.failure("URL for client management point does not use https scheme", { required: "https", actual: uri });
	}
	if (!token) {
		c.failure("registration_access_token must not be an empty string");
	}
	c.success("Verified dynamic registration management credentials", {
		registration_client_uri: uri,
		registration_access_token: token,
	});
}

/** upstream: condition/client/VerifyDynamicRegistrationResponseClientCredentials.java */
export function verifyDynamicRegistrationResponseClientCredentials(client: Client, ...requirements: string[]): void {
	const c: Condition = condition("VerifyDynamicRegistrationResponseClientCredentials", ...requirements);
	if (client.client_secret === undefined) {
		c.log(
			"Skipped check for valid credential information for token_endpoint_auth_method in client registration response",
		);
		return;
	}
	const expiresAt = client["client_secret_expires_at"];
	if (expiresAt === undefined) {
		c.failure("Missing client_secret_expires_at for token_endpoint_auth_method in client registration response");
	}
	c.success("Found required credential information for token_endpoint_auth_method in client registration response", {
		client_secret: client.client_secret,
		client_secret_expires_at: expiresAt,
	});
}

/**
 * Registers a client and verifies the registration response.
 *
 * upstream: AbstractOIDCCServerTest.configureDynamicClient: sequence/client/OIDCCCreateDynamicClientRegistrationRequest.java
 * + sequence/client/CallDynamicRegistrationEndpointAndVerifySuccessfulResponse.java
 */
export async function registerClient(opts: {
	testId: string;
	metadata: ServerMetadata;
	config: TestConfig;
	/** "client" or "client2" */
	configKey?: string;
	responseType: string;
	clientAuthType: string;
	redirectUri: string;
	/** The client's keys, when a module does not use GenerateRS256ClientJWKs (e.g. GenerateRS256ClientJWKsWithKeyID) */
	generateKeys?: () => ClientKeys | Promise<ClientKeys>;
	/** See {@link RegistrationRequestOptions.jwksUri} */
	jwksUri?: string;
	/** See {@link RegistrationRequestOptions.customize} */
	customize?: (registrationRequest: Record<string, unknown>) => void;
}): Promise<RegisteredClient> {
	const original = storeOriginalClientConfiguration(opts.config, opts.configKey);
	const clientName = extractClientNameFromStoredConfig(original);
	const initialAccessToken = extractInitialAccessTokenFromStoredConfig(original);

	const { request: registrationRequest, keys } = await createDynamicClientRegistrationRequest(opts.testId, {
		clientName,
		responseType: opts.responseType,
		clientAuthType: opts.clientAuthType,
		redirectUri: opts.redirectUri,
		generateKeys: opts.generateKeys,
		jwksUri: opts.jwksUri,
		customize: opts.customize,
	});

	const response = await callDynamicRegistrationEndpoint(
		opts.metadata,
		registrationRequest,
		initialAccessToken,
		"RFC7591-3.1",
		"OIDCR-3.2",
	);
	soft(() => ensureContentTypeJson(response, "OIDCR-3.2"));
	soft(() => ensureHttpStatusCodeIs201(response, "OIDCR-3.2"));
	soft(() => checkNoErrorFromDynamicRegistrationEndpoint(response, "OIDCR-3.2"));
	const client = extractDynamicRegistrationResponse(response, "OIDCR-3.2");
	soft(() => verifyClientManagementCredentials(client, "OIDCR-3.2"));
	soft(() => verifyDynamicRegistrationResponseClientCredentials(client, "OIDCR-3.2"));
	return { client, keys, dynamic: true, registrationRequest };
}

/** upstream: condition/client/GetStaticClientConfiguration.java (GetStaticClient2Configuration for "client2") */
export function getStaticClientConfiguration(config: TestConfig, key = "client"): Client {
	const name = key === "client2" ? "GetStaticClient2Configuration" : "GetStaticClientConfiguration";
	const c: Condition = condition(name);
	const client = config[key];
	if (key === "client2") {
		// upstream: condition/client/GetStaticClient2Configuration.java has its own messages
		if (client == null || typeof client !== "object" || Array.isArray(client)) {
			c.failure("Definition for client2 not present in supplied configuration");
		}
		c.success("Found a static second client object", client as Record<string, unknown>);
		return structuredClone(client) as Client;
	}
	if (client == null || typeof client !== "object" || Array.isArray(client)) {
		c.failure("As static client was selected, the test configuration must contain a client configuration");
	}
	const clientId = (client as Record<string, unknown>)["client_id"];
	if (clientId === undefined) {
		c.failure("As static client was selected, the test configuration must contain a client_id");
	}
	if (typeof clientId !== "string") {
		c.failure("client_id in test configuration is not a string");
	}
	c.success("Found a static client object", client as Record<string, unknown>);
	return structuredClone(client) as Client;
}

/**
 * The client's own private keys from the configuration (`client.jwks`), when there are any: used for
 * private_key_jwt and to decrypt encrypted id_tokens.
 *
 * upstream: AbstractOIDCCServerTest.ConfigureStaticClient: condition/client/ValidateClientJWKsPrivatePart.java,
 * ExtractJWKsFromStaticClientConfiguration.java, condition/common/CheckDistinctKeyIdValueInClientJWKs.java (each
 * skipped when client.jwks is missing)
 */
export function configureStaticClientKeys(client: Client): ClientKeys | null {
	const jwks = client["jwks"] as Jwks | undefined;
	if (jwks == null) {
		skipped("ValidateClientJWKsPrivatePart", { element: ["client", "jwks"] }, "RFC7517-1.1");
		skipped("ExtractJWKsFromStaticClientConfiguration", { element: ["client", "jwks"] });
		skipped("CheckDistinctKeyIdValueInClientJWKs", { element: ["client", "jwks"] }, "RFC7517-4.5");
		return null;
	}
	validateClientJWKsPrivatePart(jwks, "RFC7517-1.1");
	const keys = extractJWKsFromStaticClientConfiguration(jwks);
	soft(() => checkDistinctKeyIdValueInClientJWKs(keys.jwks, "RFC7517-4.5"));
	return keys;
}

/**
 * upstream: condition/client/ValidateClientJWKsPrivatePart.java (AbstractValidateJWKs.checkJWKs)
 *
 * TODO(port): AbstractValidateJWKs.verifyPrivatePart (sign/verify round trip per key) and the OKP x5c check are
 * not ported yet; a static client with private_key_jwt needs them.
 */
export function validateClientJWKsPrivatePart(jwks: unknown, ...requirements: string[]): void {
	const c: Condition = condition("ValidateClientJWKsPrivatePart", ...requirements);
	if (jwks == null) {
		c.failure("Couldn't find JWKS in configuration");
	}
	if (typeof jwks !== "object" || Array.isArray(jwks)) {
		c.failure(
			"Invalid JWKS (Json Web Key Set) in configuration - it must be a JSON object that contains a 'keys' array.",
			{
				jwks,
			},
		);
	}
	const set = jwks as Record<string, unknown>;
	if (!Array.isArray(set["keys"])) {
		c.failure("Keys array not found in JWKS", { jwks });
	}
	const issues = findStructurallyInvalidKeys(set as never);
	if (issues.length > 0) {
		c.failure("Invalid JWK in JWKS: the key at index " + issues[0].index + " " + issues[0].detail, {
			issues: issuesToJson(issues),
		});
	}
	for (const key of set["keys"] as Record<string, unknown>[]) {
		try {
			parseJWK(JSON.stringify(key));
		} catch (e) {
			if (e instanceof ParseException) {
				c.failureFrom("Invalid JWK", e, { key });
			}
			throw e;
		}
	}
	c.success(
		"Valid client JWKs: keys are valid JSON, contain the required fields, the private/public exponents match and are correctly encoded using unpadded base64url",
	);
}

/** upstream: condition/client/ExtractJWKsFromStaticClientConfiguration.java (AbstractExtractJWKsFromClientConfiguration) */
export function extractJWKsFromStaticClientConfiguration(jwks: unknown): ClientKeys {
	const c: Condition = condition("ExtractJWKsFromStaticClientConfiguration");
	if (jwks == null) {
		c.failure("Couldn't find JWKs in client configuration");
	}
	if (typeof jwks !== "object" || Array.isArray(jwks)) {
		c.failure("Invalid JWKs in client configuration - JSON decode failed");
	}
	let pub: Jwks;
	try {
		pub = publicJwks(parseJWKSet(JSON.stringify(jwks)));
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Invalid JWKs in client configuration (private key is required), JWKSet.parse failed", e, {
				client_jwks: jwks,
			});
		}
		throw e;
	}
	c.success("Extracted client JWK", { client_jwks: jwks, client_public_jwks: pub });
	return { jwks: jwks as Jwks, publicJwks: pub };
}

/**
 * The scope of the authorization requests (`client.override_openid_scope` replaces "openid").
 *
 * upstream: condition/client/SetScopeInClientConfigurationToOpenId.java (AbstractSetScopeInClientConfiguration)
 */
export function setScopeInClientConfigurationToOpenId(client: Client): void {
	const override = client["override_openid_scope"];
	const scope = typeof override === "string" ? override : "openid";
	client.scope = scope;
	condition("SetScopeInClientConfigurationToOpenId").log(`Set scope in client configuration to "${scope}"`, { scope });
}

/** upstream: condition/client/UnregisterDynamicallyRegisteredClient.java */
export async function unregisterDynamicallyRegisteredClient(client: Client): Promise<void> {
	const c: Condition = condition("UnregisterDynamicallyRegisteredClient");
	const token = client.registration_access_token;
	if (!token) {
		c.log("Couldn't find registration_access_token.");
		return;
	}
	const uri = client.registration_client_uri;
	if (!uri) {
		c.log("Couldn't find registration_client_uri.");
		return;
	}
	let res;
	try {
		res = await request(c.name, {
			url: uri,
			method: "DELETE",
			headers: { accept: "application/json", Authorization: "Bearer " + token },
		});
	} catch (e) {
		if (e instanceof HttpError) {
			c.failureFrom("Call to registration client uri " + uri + " failed - " + e.message, e);
		}
		throw e;
	}
	if (res.status >= 400) {
		c.failure("Error when calling registration_client_uri", {
			code: res.status,
			status: res.statusText,
			body: res.body ?? "",
		});
	}
	if (res.status !== 204) {
		c.failure("registration_client_uri returned a http status code other than 204 No Content", { code: res.status });
	}
	c.success("Client successfully unregistered");
}

/** upstream: condition/client/AbstractSetScopeInClientConfiguration.java */
function setScopeInClientConfiguration(c: Condition, client: Client, scope: string, additionalLogMsg = ""): void {
	client.scope = scope;
	c.log(`Set scope in client configuration to "${scope}"` + additionalLogMsg, { scope });
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdAddress.java */
export function setScopeInClientConfigurationToOpenIdAddress(client: Client): void {
	setScopeInClientConfiguration(condition("SetScopeInClientConfigurationToOpenIdAddress"), client, "openid address");
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile.java */
export function setScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile(client: Client): void {
	setScopeInClientConfiguration(
		condition("SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile"),
		client,
		"openid email phone address profile",
	);
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdEmail.java */
export function setScopeInClientConfigurationToOpenIdEmail(client: Client): void {
	setScopeInClientConfiguration(condition("SetScopeInClientConfigurationToOpenIdEmail"), client, "openid email");
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdPhone.java */
export function setScopeInClientConfigurationToOpenIdPhone(client: Client): void {
	setScopeInClientConfiguration(condition("SetScopeInClientConfigurationToOpenIdPhone"), client, "openid phone");
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdProfile.java */
export function setScopeInClientConfigurationToOpenIdProfile(client: Client): void {
	setScopeInClientConfiguration(condition("SetScopeInClientConfigurationToOpenIdProfile"), client, "openid profile");
}

/**
 * Reads the client's registration from the client configuration endpoint (registration_client_uri, with the
 * registration_access_token); any status is a response, the body must be JSON.
 *
 * upstream: condition/client/CallClientConfigurationEndpoint.java
 */
export async function callClientConfigurationEndpoint(
	client: Client,
	...requirements: string[]
): Promise<EndpointResponse> {
	const c: Condition = condition("CallClientConfigurationEndpoint", ...requirements);
	const accessToken = client.registration_access_token;
	if (!accessToken) {
		c.failure("Couldn't find registration_access_token in client object.");
	}
	const uri = client.registration_client_uri;
	if (!uri) {
		c.failure("Couldn't find registration_client_uri in client object.");
	}
	let res;
	try {
		res = await request(c.name, {
			url: uri,
			method: "GET",
			headers: { Accept: "application/json", "Accept-Charset": "utf-8", Authorization: "Bearer " + accessToken },
		});
	} catch (e) {
		if (e instanceof HttpError) {
			const cause = e.cause instanceof Error ? e.cause.message : e.message;
			c.failureFrom("Call to registration_client_uri " + uri + " failed - " + cause, e);
		}
		throw e;
	}
	// AbstractCondition.convertJsonResponseForEnvironment without allowParseFailure
	const response = endpointResponse("registration_client_uri", res);
	if (!res.body) {
		c.failure("Empty response from the registration_client_uri endpoint");
	}
	const parsed = jsonBody(res);
	if (!parsed.ok) {
		c.failureFrom(
			"Response from registration_client_uri endpoint does not appear to be JSON.",
			new SyntaxError(parsed.error),
			{
				response: res.body,
			},
		);
	}
	if (response.body_json === undefined) {
		c.failure("registration_client_uri endpoint did not return a JSON object.", { response: res.body });
	}
	c.success("Called registration_client_uri", { ...response });
	return response;
}

/** upstream: condition/client/CheckRegistrationClientEndpointContentTypeHttpStatus200.java */
export function checkRegistrationClientEndpointContentTypeHttpStatus200(
	response: EndpointResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckRegistrationClientEndpointContentTypeHttpStatus200", ...requirements);
	const expected = 200;
	if (response.status == null) {
		c.failure("Http status can not be null.");
	}
	if (response.status !== expected) {
		c.failure("Invalid http status", { actual: response.status, expected });
	}
	c.success("registration_client_endpoint_response http status code was " + expected);
}

/** upstream: condition/client/CheckRegistrationClientEndpointContentType.java */
export function checkRegistrationClientEndpointContentType(
	response: EndpointResponse,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckRegistrationClientEndpointContentType", ...requirements);
	const contentType = response.headers["content-type"];
	if (typeof contentType !== "string" || !contentType) {
		c.failure("Couldn't find content-type header in registration_client_endpoint_response");
	}
	const expected = "application/json";
	if (contentType.split(";")[0].trim() !== expected) {
		c.failure("Invalid content-type header in registration_client_endpoint_response", {
			expected,
			actual: contentType,
		});
	}
	c.success("registration_client_endpoint_response Content-Type: header is " + expected);
}

/** upstream: condition/client/AbstractCheckErrorFromDynamicRegistrationEndpoint.java */
function checkErrorFromDynamicRegistrationEndpoint(
	name: string,
	response: EndpointResponse,
	permitted: string[],
	requirements: string[],
): void {
	const c: Condition = condition(name, ...requirements);
	const error = (response.body_json as Record<string, unknown> | undefined)?.["error"];
	if (typeof error !== "string" || !error) {
		c.failure("'error' field not found in response from dynamic registration endpoint");
	}
	if (!permitted.includes(error)) {
		c.failure("'error' field has unexpected value", { permitted, actual: error });
	}
	c.success("Dynamic registration endpoint returned 'error'", { permitted, error });
}

/** upstream: condition/client/CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata.java */
export function checkErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata(
	response: EndpointResponse,
	...requirements: string[]
): void {
	checkErrorFromDynamicRegistrationEndpoint(
		"CheckErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata",
		response,
		["invalid_client_metadata"],
		requirements,
	);
}

/** upstream: condition/client/CheckErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata.java */
export function checkErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata(
	response: EndpointResponse,
	...requirements: string[]
): void {
	checkErrorFromDynamicRegistrationEndpoint(
		"CheckErrorFromDynamicRegistrationEndpointIsInvalidRedirectUriOrInvalidClientMetadata",
		response,
		["invalid_redirect_uri", "invalid_client_metadata"],
		requirements,
	);
}

/**
 * A JWK set holding the client secret as a symmetric signing key (`client_secret_jwt_alg`, default HS256), for
 * clients that have no keys of their own.
 *
 * upstream: condition/client/GenerateJWKsFromClientSecret.java
 */
export function generateJWKsFromClientSecret(client: Client): Jwks {
	const c: Condition = condition("GenerateJWKsFromClientSecret");
	const secret = client.client_secret;
	if (!secret) {
		c.failure("Couldn't find client secret");
	}
	const configuredAlg = client["client_secret_jwt_alg"];
	const alg = typeof configuredAlg === "string" && configuredAlg ? configuredAlg : "HS256";
	const bytes = Buffer.from(secret, "utf8");
	// the secret might be too short to sign with (issue #1196)
	const minSize = alg.toUpperCase() === "HS256" ? 32 : alg.toUpperCase() === "HS384" ? 48 : 64;
	if (bytes.length < minSize) {
		c.failure(
			"The client secret configured in the test plan is too short to sign a JWT with. The " +
				alg.toUpperCase() +
				" requires a secret with at least " +
				minSize +
				" bytes and the provided secret is " +
				bytes.length +
				" bytes.",
		);
	}
	// new OctetSequenceKey.Builder(secret).algorithm(alg).keyUse(KeyUse.SIGNATURE).build(): no key id
	const jwks = privateJwks({ keys: [{ kty: "oct", use: "sig", alg, k: bytes.toString("base64url") }] });
	c.success("Generated JWK Set from symmetric key", { client_jwks: jwks });
	return jwks;
}

/**
 * How a test module sets up its client (the `configureClient(setup)` fixture; the `client` / `client2` fixtures use the
 * defaults). upstream: the overrides of AbstractOIDCCServerTest.configureClient / createDynamicClientRegistrationRequest /
 * completeClientConfiguration, and AbstractOIDCCMultipleClient's second client.
 */
export interface ClientSetup {
	/**
	 * Which client of the configuration: "client2" is the second client of the multiple client modules (its
	 * unregistration block is prefixed "Second client: "). Default "client".
	 */
	configKey?: "client" | "client2";
	/** The configuration key of a static client (default `configKey`, e.g. "client_secret_post") */
	staticConfigKey?: string;
	/**
	 * What the module adds to the dynamic registration request, after the OIDCC defaults and before it is sent
	 * (upstream createDynamicClientRegistrationRequest overrides; not called for a static client)
	 */
	customize?: (registrationRequest: Record<string, unknown>) => void;
	/**
	 * The module's completeClientConfiguration (e.g. the scope), in place of the default
	 * SetScopeInClientConfigurationToOpenId
	 */
	completeClientConfiguration?: (op: Pick<Op, "metadata" | "variant">, client: Client) => void;
	/**
	 * False for the modules built on upstream's AbstractOIDCCDynamicRegistrationTest: their client is registered and
	 * its scope set, without the EnsureServerConfigurationSupports<client authentication> check. Default true.
	 */
	checkClientAuthSupported?: boolean;
	/** The redirect_uri to register (default: the suite's, `op.redirectUri`) */
	redirectUri?: string;
	/** See registerClient(): keys other than GenerateRS256ClientJWKs' (e.g. generateRS256ClientJWKsWithKeyID) */
	generateKeys?: () => ClientKeys | Promise<ClientKeys>;
	/** See createDynamicRegistrationRequest(): the keys are registered by reference, served by the suite at this URL */
	jwksUri?: string;
}

/** upstream: condition/client/AddIdTokenSigningAlgNoneToDynamicRegistrationRequest.java */
export function addIdTokenSigningAlgNoneToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
): void {
	registrationRequest["id_token_signed_response_alg"] = "none";
	condition("AddIdTokenSigningAlgNoneToDynamicRegistrationRequest").log(
		"Added id_token_signed_response_alg to dynamic registration request",
		{ dynamic_registration_request: registrationRequest },
	);
}

/** upstream: condition/client/AddRefreshTokenGrantTypeToDynamicRegistrationRequest.java (AbstractAddGrantTypeToDynamicRegistrationRequest) */
export function addRefreshTokenGrantTypeToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
): void {
	const grantTypes = [...((registrationRequest["grant_types"] as string[] | undefined) ?? []), "refresh_token"];
	registrationRequest["grant_types"] = grantTypes;
	condition("AddRefreshTokenGrantTypeToDynamicRegistrationRequest").log("Added 'refresh_token' to 'grant_types'", {
		grant_types: grantTypes,
	});
}

/** upstream: condition/client/AddRequestUriToDynamicRegistrationRequest.java */
export function addRequestUriToDynamicRegistrationRequest(
	registrationRequest: Record<string, unknown>,
	requestUri: string,
): void {
	const c: Condition = condition("AddRequestUriToDynamicRegistrationRequest");
	if (!requestUri) {
		c.failure("No request_uri found in environment; this is likely a bug in the test module");
	}
	registrationRequest["request_uris"] = [requestUri];
	c.log("Added request_uris array to dynamic registration request", {
		dynamic_registration_request: registrationRequest,
	});
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdOfflineAccess.java */
export function setScopeInClientConfigurationToOpenIdOfflineAccess(client: Client): void {
	setScopeInClientConfiguration(
		condition("SetScopeInClientConfigurationToOpenIdOfflineAccess"),
		client,
		"openid offline_access",
		" so that a refresh token is issued",
	);
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess.java */
export function setScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess(
	metadata: ServerMetadata,
	client: Client,
): void {
	const c: Condition = condition("SetScopeInClientConfigurationToOpenIdOfflineAccessIfServerSupportsOfflineAccess");
	const scopesSupported = metadata["scopes_supported"];
	if (scopesSupported === undefined) {
		c.log(
			"scopes_supported is not present in the discovery document, so assuming server does not support 'offline_access' scope and hence not adding it to the list of scopes to be requested",
		);
		return;
	}
	if (!Array.isArray(scopesSupported)) {
		c.failure("'scopes_supported' is not a array");
	}
	if (!(scopesSupported as string[]).includes("offline_access")) {
		c.log("scopes supported does not contain 'offline_access' so not adding it to the list of scopes to be requested", {
			scopes_supported: scopesSupported,
		});
		return;
	}
	setScopeInClientConfiguration(c, client, "openid offline_access", "as 'scope_supported' contains 'offline_access'");
}

/** upstream: condition/client/GenerateRS256ClientJWKsWithKeyID.java (the kid is the key's thumbprint) */
export async function generateRS256ClientJWKsWithKeyID(): Promise<ClientKeys> {
	const key = generateRsaJwk("RS256", "sig");
	key["kid"] = await calculateJwkThumbprint(key as never, "sha256");
	const jwks = privateJwks({ keys: [key] });
	const pub = publicJwks({ keys: [key] });
	condition("GenerateRS256ClientJWKsWithKeyID").success("Generated client JWKs", {
		client_jwks: jwks,
		public_client_jwks: pub,
	});
	return { jwks, publicJwks: pub };
}

/**
 * The client_name and initial access token of the configuration's `client` (or `client2`) object, as the modules
 * that register a client themselves take them.
 *
 * upstream: AbstractOIDCCServerTest.configureClient / AbstractOIDCCDynamicRegistrationTest.configure:
 * StoreOriginalClientConfiguration, ExtractClientNameFromStoredConfig, ExtractInitialAccessTokenFromStoredConfig
 */
export function extractDynamicRegistrationSettings(
	config: TestConfig,
	configKey = "client",
): { clientName: string | null; initialAccessToken: string | null } {
	const original = storeOriginalClientConfiguration(config, configKey);
	return {
		clientName: extractClientNameFromStoredConfig(original),
		initialAccessToken: extractInitialAccessTokenFromStoredConfig(original),
	};
}

/**
 * The registration request of the OIDCC tests with freshly generated keys (GenerateRS256ClientJWKs unless
 * `generateKeys`, CheckDistinctKeyIdValueInClientJWKs, createDynamicRegistrationRequest), without calling the endpoint:
 * registerClient() sends it, the modules that expect the registration to fail send it themselves.
 */
export async function createDynamicClientRegistrationRequest(
	testId: string,
	opts: Omit<RegistrationRequestOptions, "publicJwks"> & { generateKeys?: () => ClientKeys | Promise<ClientKeys> },
): Promise<{ request: Record<string, unknown>; keys: ClientKeys }> {
	const keys = await (opts.generateKeys ?? generateRS256ClientJWKs)();
	soft(() => checkDistinctKeyIdValueInClientJWKs(keys.jwks, "RFC7517-4.5"));
	const registrationRequest = createDynamicRegistrationRequest(testId, { ...opts, publicJwks: keys.publicJwks });
	return { request: registrationRequest, keys };
}

/** What a `dynamic_registration_request` entry logs */
function logRegistrationRequest(name: string, msg: string, req: Record<string, unknown>): void {
	condition(name).log(msg, { dynamic_registration_request: req });
}

/** A URL on the suite's host (scheme, host and port of `baseUrl`) */
function suiteHostUrl(c: Condition, baseUrl: string, path: string, what: string): string {
	try {
		const base = new URL(baseUrl);
		// new URI(scheme, null, host, port, path, null, null)
		return base.protocol + "//" + base.hostname + (base.port !== "" ? ":" + base.port : "") + path;
	} catch (e) {
		return c.failureFrom("Failed to generate " + what + " URI", e);
	}
}

/** upstream: condition/client/CreateLogoUri.java */
export function createLogoUri(baseUrl: string): string {
	const c: Condition = condition("CreateLogoUri");
	const logoUri = suiteHostUrl(c, baseUrl, "/images/openid.png", "logo");
	c.log("Generated logo URI", { logo_uri: logoUri });
	return logoUri;
}

/** upstream: condition/client/AddLogoUriToDynamicRegistrationRequest.java */
export function addLogoUriToDynamicRegistrationRequest(req: Record<string, unknown>, logoUri: string): void {
	req["logo_uri"] = logoUri;
	logRegistrationRequest(
		"AddLogoUriToDynamicRegistrationRequest",
		"Added logo_uri to dynamic registration request",
		req,
	);
}

/**
 * As per https://openid.net/specs/openid-connect-registration-1_0.html#Impersonation the policy_uri should have the
 * same host as the redirect_uris, so it is a page on the suite's host.
 *
 * upstream: condition/client/CreatePolicyUri.java
 */
export function createPolicyUri(baseUrl: string): string {
	const c: Condition = condition("CreatePolicyUri");
	// UPSTREAM: the failure message says "logo URI" although this condition generates the policy URI
	const policyUri = suiteHostUrl(c, baseUrl, "/login.html", "logo");
	c.log("Generated policy URI", { policy_uri: policyUri });
	return policyUri;
}

/** upstream: condition/client/AddPolicyUriToDynamicRegistrationRequest.java */
export function addPolicyUriToDynamicRegistrationRequest(req: Record<string, unknown>, policyUri: string): void {
	req["policy_uri"] = policyUri;
	logRegistrationRequest(
		"AddPolicyUriToDynamicRegistrationRequest",
		"Added policy_uri to dynamic registration request",
		req,
	);
}

/** upstream: condition/client/CreateTosUri.java */
export function createTosUri(): string {
	const tosUri = "https://openid.net";
	condition("CreateTosUri").log("Generated TOS URI", { tos_uri: tosUri });
	return tosUri;
}

/** upstream: condition/client/AddTosUriToDynamicRegistrationRequest.java */
export function addTosUriToDynamicRegistrationRequest(req: Record<string, unknown>, tosUri: string): void {
	req["tos_uri"] = tosUri;
	logRegistrationRequest("AddTosUriToDynamicRegistrationRequest", "Added tos_uri to dynamic registration request", req);
}

/** A REVIEW entry asking for a screenshot; the browser automation fills the placeholder ("update-image-placeholder") */
function browserInteractionPlaceholder(name: string, msg: string, requirements: string[]): string {
	const placeholder = randomAlphanumeric(10);
	condition(name, ...requirements).review(msg, { upload: placeholder });
	return placeholder;
}

/** upstream: condition/client/ExpectLoginPageWithLogo.java; returns the placeholder to wait for */
export function expectLoginPageWithLogo(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectLoginPageWithLogo",
		"The login page should show the OpenID logo (as displayed on this server) - upload a screenshot of the login page.",
		requirements,
	);
}

/** upstream: condition/client/ExpectLoginPageWithPolicyLink.java; returns the placeholder to wait for */
export function expectLoginPageWithPolicyLink(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectLoginPageWithPolicyLink",
		"The login page should show a link to a policy document - upload a screenshot of the login page.",
		requirements,
	);
}

/** upstream: condition/client/ExpectLoginPageWithTosLink.java; returns the placeholder to wait for */
export function expectLoginPageWithTosLink(...requirements: string[]): string {
	return browserInteractionPlaceholder(
		"ExpectLoginPageWithTosLink",
		"The login page should show a link to a TOS document - upload a screenshot of the login page.",
		requirements,
	);
}

/** upstream: condition/client/CreateJwksUri.java: the suite serves the client's public keys at `<base url>/client1_jwks` */
export function createJwksUri(baseUrl: string): string {
	const c: Condition = condition("CreateJwksUri");
	if (baseUrl.length === 0) {
		c.failure("Base URL is empty");
	}
	// see https://gitlab.com/openid/conformance-suite/wikis/Developers/Build-&-Run#ciba-notification-endpoint
	const jwksUri = baseUrl + "/client1_jwks";
	c.success("Created JWKs URI", { jwks_uri: jwksUri });
	return jwksUri;
}

/** upstream: condition/client/CreateSectorRedirectUris.java */
export function createSectorRedirectUris(redirectUri: string): string[] {
	const value = [redirectUri];
	condition("CreateSectorRedirectUris").log("Created sector redirect URIs", { sector_redirect_uris: { value } });
	return value;
}

/** upstream: condition/client/CreateInvalidSectorRedirectUris.java */
export function createInvalidSectorRedirectUris(): string[] {
	const value = ["https://example.com/op"];
	condition("CreateInvalidSectorRedirectUris").log("Created invalid sector redirect URIs", {
		sector_redirect_uris: { value },
	});
	return value;
}

/** upstream: condition/client/AddSubjectTypePairwiseToDynamicRegistrationRequest.java */
export function addSubjectTypePairwiseToDynamicRegistrationRequest(req: Record<string, unknown>): void {
	req["subject_type"] = "pairwise";
	logRegistrationRequest(
		"AddSubjectTypePairwiseToDynamicRegistrationRequest",
		"Added pairwise subject_type to dynamic registration request",
		req,
	);
}

/** upstream: condition/client/AddSectorIdentifierUriToDynamicRegistrationRequest.java */
export function addSectorIdentifierUriToDynamicRegistrationRequest(
	req: Record<string, unknown>,
	baseUrl: string,
): void {
	// the sector_identifier_uri must be reachable by the OP: it is served by the suite
	req["sector_identifier_uri"] = baseUrl + "/redirect_uris.json";
	logRegistrationRequest(
		"AddSectorIdentifierUriToDynamicRegistrationRequest",
		"Added sector_identifier_uri to dynamic registration request",
		req,
	);
}

/** upstream: condition/client/AddFragmentToRedirectUri.java */
export function addFragmentToRedirectUri(redirectUri: string): string {
	const url = new URL(redirectUri);
	url.hash = "foobar";
	const withFragment = url.toString();
	condition("AddFragmentToRedirectUri").log("Updated redirect_uri", { redirect_uri: withFragment });
	return withFragment;
}

/** upstream: condition/client/AddQueryToRedirectUri.java */
export function addQueryToRedirectUri(redirectUri: string): string {
	const url = new URL(redirectUri);
	url.searchParams.append("bar", "foo");
	const withQuery = url.toString();
	condition("AddQueryToRedirectUri").log("Updated redirect_uri", { redirect_uri: withQuery });
	return withQuery;
}

/** upstream: condition/client/AddMultipleRedirectUriToDynamicRegistrationRequest.java */
export function addMultipleRedirectUriToDynamicRegistrationRequest(
	req: Record<string, unknown>,
	redirectUri: string,
): void {
	const c: Condition = condition("AddMultipleRedirectUriToDynamicRegistrationRequest");
	if (!redirectUri) {
		c.failure("No redirect_uri found");
	}
	req["redirect_uris"] = [redirectUri, "https://example.org/redirect"];
	c.log("Added redirect_uris array to dynamic registration request", { dynamic_registration_request: req });
}

/** upstream: condition/client/AddIdTokenSigningAlgRS256ToDynamicRegistrationRequest.java */
export function addIdTokenSigningAlgRS256ToDynamicRegistrationRequest(req: Record<string, unknown>): void {
	req["id_token_signed_response_alg"] = "RS256";
	logRegistrationRequest(
		"AddIdTokenSigningAlgRS256ToDynamicRegistrationRequest",
		"Added id_token_signed_response_alg to dynamic registration request",
		req,
	);
}

/** upstream: condition/client/AddUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest.java */
export function addUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest(
	req: Record<string, unknown>,
	...requirements: string[]
): void {
	req["userinfo_signed_response_alg"] = "RS256";
	condition("AddUserinfoSignedResponseAlgRS256ToDynamicRegistrationRequest", ...requirements).log(
		"Added userinfo_signed_response_alg=RS256 to dynamic registration request",
		{ dynamic_registration_request: req },
	);
}

/** upstream: condition/client/AddRequestObjectSigningAlgRS256ToDynamicRegistrationRequest.java */
export function addRequestObjectSigningAlgRS256ToDynamicRegistrationRequest(req: Record<string, unknown>): void {
	req["request_object_signing_alg"] = "RS256";
	logRegistrationRequest(
		"AddRequestObjectSigningAlgRS256ToDynamicRegistrationRequest",
		"Added request_object_signing_alg to dynamic registration request",
		req,
	);
}
