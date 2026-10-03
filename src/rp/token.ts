/**
 * The emulated OP's token endpoint: the client authentication and code exchange checks upstream runs on the RP's
 * token request, and the token response (access token, id_token).
 */
import { block, condition, soft, type Condition } from "../suite/conditions.ts";
import { currentLog } from "../suite/log.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { calculateAtHash, createIdToken } from "./id-token.ts";
import { failTest, type EmulatedOp } from "./op.ts";
import type { RpClient } from "./registration.ts";

/** The access token the OP issued (upstream env "access_token", "token_type", "at_hash") */
export interface IssuedTokens {
	accessToken: string;
	tokenType: "Bearer";
	/** null when the id_token is not signed (alg none) */
	atHash: string | null;
}

/** upstream env "client_authentication" */
export interface ClientAuthentication {
	client_id: string;
	client_secret: string;
	method: string;
}

/** A form parameter read as a string (OIDFJSON.getString): null when absent, an error when repeated */
function formParam(req: IncomingRequest, name: string): string | null {
	const v = req.body_form_params?.[name];
	if (v == null) {
		return null;
	}
	if (typeof v !== "string") {
		throw new Error("getString called on something that is not a string: " + JSON.stringify(v));
	}
	return v;
}

/** upstream: condition/as/CheckClientIdMatchesOnTokenRequestIfPresent.java */
export function checkClientIdMatchesOnTokenRequestIfPresent(
	req: IncomingRequest,
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("CheckClientIdMatchesOnTokenRequestIfPresent", ...requirements);
	const clientId = formParam(req, "client_id");
	if (!clientId) {
		c.log("client_id not present, nothing to check");
		return;
	}
	if (client.client_id === clientId) {
		c.success("Extracted client_id matches the expected value", { client_id: clientId });
		return;
	}
	c.failure(`client_id on the request ${clientId} does not match the expected one ${client.client_id}`, {
		expected: client.client_id,
		actual: clientId,
	});
}

/** Java URLDecoder.decode: form decoding, '+' is a space */
function formDecode(s: string): string {
	return decodeURIComponent(s.replace(/\+/g, " "));
}

/** upstream: condition/as/ExtractClientCredentialsFromBasicAuthorizationHeader.java */
export function extractClientCredentialsFromBasicAuthorizationHeader(
	req: IncomingRequest,
	...requirements: string[]
): ClientAuthentication {
	const c: Condition = condition("ExtractClientCredentialsFromBasicAuthorizationHeader", ...requirements);
	const auth = req.headers["authorization"];
	if (!auth || typeof auth !== "string") {
		c.failure(
			"This test expected the client to perform client_secret_basic client authorization, but the incoming http request does not contain an authorization header",
		);
	}
	if (!auth.toLowerCase().startsWith("basic")) {
		c.failure("Not a basic authorization header", { auth });
	}
	const encoded = auth.substring("Basic ".length);
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
		// Java: Base64.getDecoder().decode() throws IllegalArgumentException
		throw new Error("Illegal base64 character");
	}
	const parts = Buffer.from(encoded, "base64").toString("utf8").split(":");
	if (parts.length !== 2) {
		c.failure("Unexpected number of parts to authorization header", { basic_auth: parts });
	}
	const authentication: ClientAuthentication = {
		client_id: formDecode(parts[0]),
		client_secret: formDecode(parts[1]),
		method: "client_secret_basic",
	};
	c.success("Extracted client authentication", { ...authentication });
	return authentication;
}

/** upstream: condition/as/ExtractClientCredentialsFromFormPost.java */
export function extractClientCredentialsFromFormPost(
	req: IncomingRequest,
	...requirements: string[]
): ClientAuthentication {
	const c: Condition = condition("ExtractClientCredentialsFromFormPost", ...requirements);
	const clientId = formParam(req, "client_id");
	const clientSecret = formParam(req, "client_secret");
	if (!clientId || !clientSecret) {
		c.failure("Couldn't find client credentials in form post");
	}
	const authentication: ClientAuthentication = {
		client_id: clientId,
		client_secret: clientSecret,
		method: "client_secret_post",
	};
	c.success("Extracted client authentication", { ...authentication });
	return authentication;
}

/** upstream: condition/as/ValidateClientIdAndSecret.java */
export function validateClientIdAndSecret(
	authentication: ClientAuthentication,
	client: RpClient,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateClientIdAndSecret", ...requirements);
	if (!authentication.client_id) {
		c.failure("Couldn't find client id in request", { client_authentication: authentication });
	}
	if (client.client_id === authentication.client_id && client["client_secret"] === authentication.client_secret) {
		c.success("Client id and secret match");
		return;
	}
	c.failure("Client authentication failed", {
		expected_client_id: client.client_id,
		received_client_id: authentication.client_id,
		expected_client_secret: client["client_secret"],
		received_client_secret: authentication.client_secret,
	});
}

/**
 * The client authenticates with the variant's method.
 *
 * upstream: sequence/as/OIDCCValidateClientAuthenticationWithClientSecretBasic.java,
 * OIDCCValidateClientAuthenticationWithClientSecretPost.java, OIDCCValidateClientAuthenticationWithNone.java
 */
export function validateClientAuthentication(req: IncomingRequest, client: RpClient, clientAuthType: string): void {
	if (clientAuthType === "client_secret_basic") {
		const authentication = extractClientCredentialsFromBasicAuthorizationHeader(req, "OIDCC-9");
		soft(() => validateClientIdAndSecret(authentication, client, "RFC6749-2.3.1"));
	} else if (clientAuthType === "client_secret_post") {
		const authentication = soft(() => extractClientCredentialsFromFormPost(req, "OIDCC-9"));
		if (authentication != null) {
			soft(() => validateClientIdAndSecret(authentication, client, "RFC6749-2.3.1"));
		}
	} else if (clientAuthType !== "none") {
		// "none": upstream does not check anything (yet)
		throw new Error(`TODO(port): client_auth_type=${clientAuthType} is not supported by the emulated OP yet`);
	}
}

/** upstream: condition/as/ValidateAuthorizationCode.java */
export function validateAuthorizationCode(
	req: IncomingRequest,
	expected: string | null,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateAuthorizationCode", ...requirements);
	const actual = formParam(req, "code");
	if (!expected) {
		c.failure("Couldn't find authorization code to compare");
	}
	if (expected !== actual) {
		c.failure("Didn't find matching authorization code", { expected, actual });
	}
	c.success("Found authorization code", { authorization_code: actual });
}

/** upstream: condition/as/ValidateRedirectUriForTokenEndpointRequest.java */
export function validateRedirectUriForTokenEndpointRequest(
	req: IncomingRequest,
	expected: string | undefined,
	...requirements: string[]
): void {
	const c: Condition = condition("ValidateRedirectUriForTokenEndpointRequest", ...requirements);
	const actual = formParam(req, "redirect_uri");
	if (!actual) {
		// OIDC 3.1.3.2 allows the OP to proceed when only one redirect_uri is registered; upstream requires it
		c.failure("redirect_uri is missing or empty", { token_endpoint_request: req });
	}
	if (actual !== expected) {
		c.failure("redirect_uri is not equal to the one used in the authorization request", { actual, expected });
	}
	c.success("redirect_uri is the same as the one used in the authorization request", { actual });
}

/** upstream: condition/as/GenerateBearerAccessToken.java */
export function generateBearerAccessToken(): string {
	const accessToken = randomAlphanumeric(50);
	condition("GenerateBearerAccessToken").success("Generated access token", { access_token: accessToken });
	return accessToken;
}

/**
 * Issues the access token (and its at_hash unless the id_token is unsigned).
 *
 * upstream: AbstractOIDCCClientTest.generateAccessToken
 */
export function generateAccessToken(op: EmulatedOp): IssuedTokens {
	const accessToken = generateBearerAccessToken();
	const atHash =
		op.signingAlg !== "none" ? calculateAtHash(accessToken, op.signingAlg as string, "OIDCC-3.3.2.11") : null;
	op.tokens = { accessToken, tokenType: "Bearer", atHash };
	return op.tokens;
}

/** upstream: condition/as/CreateTokenEndpointResponse.java */
export function createTokenEndpointResponse(
	tokens: IssuedTokens,
	idToken: string | null,
	scope: string | null,
	...requirements: string[]
): Record<string, unknown> {
	const response: Record<string, unknown> = { access_token: tokens.accessToken, token_type: tokens.tokenType };
	if (idToken) {
		response["id_token"] = idToken;
	}
	if (scope) {
		response["scope"] = scope;
	}
	// upstream logs the response without a message (logSuccess(args(...)))
	currentLog().log("CreateTokenEndpointResponse", {
		"Created token endpoint response": response,
		token_endpoint_response_headers: {},
		result: "SUCCESS",
		...(requirements.length > 0 ? { requirements } : {}),
	});
	return response;
}

/**
 * The RP's token request: grant_type, client_id and client authentication, then for authorization_code: the code
 * and redirect_uri of the authorization request, a new access token and id_token. `onCodeExchange` (the module's
 * hook, upstream's authorizationCodeGrantType override) runs before the code is checked.
 *
 * upstream: AbstractOIDCCClientTest.handleTokenEndpointRequest, authorizationCodeGrantType
 */
export async function handleTokenRequest(
	op: EmulatedOp,
	req: IncomingRequest,
): Promise<{ response: Response; tokens: Record<string, unknown> }> {
	const grantType = formParam(req, "grant_type");
	if (grantType == null) {
		failTest("Token endpoint body does not contain the mandatory 'grant_type' parameter");
	}
	return block(grantType === "refresh_token" ? "Token endpoint - Refresh Request" : "Token endpoint", async () => {
		const client = op.client;
		if (client == null) {
			throw new Error("The RP sent a token request before it registered a client");
		}
		soft(() => checkClientIdMatchesOnTokenRequestIfPresent(req, client, "RFC6749-3.2.1"));
		validateClientAuthentication(req, client, op.clientAuthType);
		if (grantType === "refresh_token") {
			failTest("refresh_token grant type is not implemented for this test");
		}
		if (grantType !== "authorization_code") {
			failTest("Got a grant type on the token endpoint we didn't understand: " + grantType);
		}
		op.options.onCodeExchange?.();
		validateAuthorizationCode(req, op.authorization?.code ?? null, "OIDCC-3.1.3.2");
		soft(() => validateRedirectUriForTokenEndpointRequest(req, op.authorization?.redirectUri, "OIDCC-3.1.3.2"));
		// UPSTREAM: CheckPkceCodeVerifier runs only when the environment has an object "code_challenge", which it never
		// has (EnsureAuthorizationRequestContainsPkceCodeChallenge stores a string): the code_verifier is not checked
		const tokens = generateAccessToken(op);
		const idToken = await createIdToken(op, true);
		const response = createTokenEndpointResponse(tokens, idToken, op.authorization?.scope ?? null, "OIDCC-3.1.3.3");
		return { response: Response.json(response), tokens: response };
	});
}
