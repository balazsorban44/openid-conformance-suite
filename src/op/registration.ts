/**
 * The client the suite uses against the OP: dynamically registered (OpenID Connect Dynamic Client Registration)
 * or taken from the test configuration, and unregistered after the test.
 */
import { condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import { endpointResponse, HttpError, request, type EndpointResponse } from "../suite/http.ts";
import { generateRsaJwk, privateJwks, publicJwks, type Jwks } from "../suite/jose.ts";
import { JWKUtil } from "../util/JWKUtil.ts";
import { ParseException } from "../util/nimbus/errors.ts";
import type { ServerMetadata } from "./discovery.ts";
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
}

/** upstream: condition/client/StoreOriginalClientConfiguration.java */
export function storeOriginalClientConfiguration(config: TestConfig, key = "client"): Record<string, unknown> {
	const c: Condition = condition("StoreOriginalClientConfiguration");
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

	req["jwks"] = opts.publicJwks;
	condition("AddPublicJwksToDynamicRegistrationRequest", "RFC7591-2").log(
		"Added client public JWKS to dynamic registration request",
		{
			dynamic_registration_request: req,
		},
	);

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
}): Promise<RegisteredClient> {
	const original = storeOriginalClientConfiguration(opts.config, opts.configKey);
	const clientName = extractClientNameFromStoredConfig(original);
	const initialAccessToken = extractInitialAccessTokenFromStoredConfig(original);

	const keys = generateRS256ClientJWKs();
	soft(() => checkDistinctKeyIdValueInClientJWKs(keys.jwks, "RFC7517-4.5"));
	const registrationRequest = createDynamicRegistrationRequest(opts.testId, {
		clientName,
		responseType: opts.responseType,
		clientAuthType: opts.clientAuthType,
		redirectUri: opts.redirectUri,
		publicJwks: keys.publicJwks,
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
	return { client, keys, dynamic: true };
}

/** upstream: condition/client/GetStaticClientConfiguration.java (GetStaticClient2Configuration for "client2") */
export function getStaticClientConfiguration(config: TestConfig, key = "client"): Client {
	const name = key === "client2" ? "GetStaticClient2Configuration" : "GetStaticClientConfiguration";
	const c: Condition = condition(name);
	const client = config[key];
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
	const issues = JWKUtil.findStructurallyInvalidKeys(set as never);
	if (issues.length > 0) {
		c.failure("Invalid JWK in JWKS: the key at index " + issues[0].index + " " + issues[0].detail, {
			issues: JWKUtil.issuesToJson(issues),
		});
	}
	for (const key of set["keys"] as Record<string, unknown>[]) {
		try {
			JWKUtil.parseJWK(JSON.stringify(key));
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
		pub = publicJwks(JWKUtil.parseJWKSet(JSON.stringify(jwks)));
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
function setScopeInClientConfiguration(name: string, client: Client, scope: string): void {
	client.scope = scope;
	condition(name).log(`Set scope in client configuration to "${scope}"`, { scope });
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdAddress.java */
export function setScopeInClientConfigurationToOpenIdAddress(client: Client): void {
	setScopeInClientConfiguration("SetScopeInClientConfigurationToOpenIdAddress", client, "openid address");
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile.java */
export function setScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile(client: Client): void {
	setScopeInClientConfiguration(
		"SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile",
		client,
		"openid email phone address profile",
	);
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdEmail.java */
export function setScopeInClientConfigurationToOpenIdEmail(client: Client): void {
	setScopeInClientConfiguration("SetScopeInClientConfigurationToOpenIdEmail", client, "openid email");
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdPhone.java */
export function setScopeInClientConfigurationToOpenIdPhone(client: Client): void {
	setScopeInClientConfiguration("SetScopeInClientConfigurationToOpenIdPhone", client, "openid phone");
}

/** upstream: condition/client/SetScopeInClientConfigurationToOpenIdProfile.java */
export function setScopeInClientConfigurationToOpenIdProfile(client: Client): void {
	setScopeInClientConfiguration("SetScopeInClientConfigurationToOpenIdProfile", client, "openid profile");
}
