/**
 * DPoP (RFC 9449) sender constraining: the client's DPoP key, the proof JWT for the PAR, token and resource
 * endpoint requests, the DPoP-Nonce the authorization / resource server supplies and the calls that retry with it.
 *
 *   const req = token.createTokenEndpointRequestForAuthorizationCodeGrant(code, redirectUri);
 *   await dpop.createDpopForTokenEndpoint(op, client, req);          // DPoP header on the request
 *   const { response, nonceError } = await dpop.callTokenEndpointAllowingDpopNonceError(op, req, client.dpop);
 *   if (nonceError) ... build the proof again with client.dpop.authorizationServerNonce and call again
 *
 * The state upstream keeps in the environment (client.dpop_private_jwk, authorization_server_dpop_nonce,
 * resource_server_dpop_nonce) is a {@link DpopState} per client: switching to the second client starts from a fresh
 * one (upstream switchToSecondClient clears the nonces).
 */
import { createHash } from "node:crypto";
import { condition, soft, type Condition } from "../suite/conditions.ts";
import type { EndpointResponse } from "../suite/http.ts";
import { generateJwkForAlg, type JWK, JOSEException, ParseException } from "../suite/jose.ts";
import { createJWSSigner } from "../suite/jose-jws.ts";
import { parseJWK, toPublicJWK } from "../suite/jose-jwk.ts";
import { parseClaimsSet } from "../suite/jose-jwt.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import type { ServerMetadata } from "./discovery.ts";
import type { Client } from "./registration.ts";
import { callTokenEndpoint, type AccessToken, type TokenRequest, type TokenResponse } from "./token.ts";
import { callProtectedResource } from "./userinfo.ts";

/** The DPoP state of one client (upstream env: client.dpop_private_jwk, the *_dpop_nonce strings) */
export interface DpopState {
	/** The client's DPoP private key (upstream "client.dpop_private_jwk"), null until GenerateDpopKey */
	key: JWK | null;
	/** The nonce the authorization server last supplied (upstream "authorization_server_dpop_nonce") */
	authorizationServerNonce: string | null;
	/** The nonce the resource server last supplied (upstream "resource_server_dpop_nonce") */
	resourceServerNonce: string | null;
}

export function newDpopState(): DpopState {
	return { key: null, authorizationServerNonce: null, resourceServerNonce: null };
}

/** The DPoP proof under construction (upstream "dpop_proof_header", "dpop_proof_claims", "dpop_proof") */
export interface DpopProof {
	header: Record<string, unknown>;
	claims: Record<string, unknown>;
}

/** A client with a DPoP state (the FAPI 2 client objects) */
export interface DpopClient {
	client: Pick<Client, "client_id"> & { dpop_signing_alg?: unknown };
	dpop: DpopState;
}

/**
 * Generates the client's DPoP key: the client's configured `dpop_signing_alg` (default PS256) unless the OP's
 * dpop_signing_alg_values_supported leaves it out, then the first algorithm the OP lists.
 *
 * upstream: condition/client/GenerateDpopKey.java
 */
export async function generateDpopKey(metadata: ServerMetadata, client: DpopClient): Promise<JWK> {
	const c: Condition = condition("GenerateDpopKey");
	let dpopSigningAlg =
		typeof client.client.dpop_signing_alg === "string" && client.client.dpop_signing_alg
			? client.client.dpop_signing_alg
			: "PS256";
	const supported = metadata["dpop_signing_alg_values_supported"];
	if (supported != null) {
		// UPSTREAM: the cast to JsonArray throws a ClassCastException for any other type
		if (!Array.isArray(supported)) {
			throw new TypeError("dpop_signing_alg_values_supported is not a JSON array");
		}
		if (!supported.includes(dpopSigningAlg)) {
			// use first alg in dpop_signing_alg_values_supported if preference is not supported
			dpopSigningAlg = String(supported[0]);
		}
	}
	let key: JWK;
	try {
		key = await generateJwkForAlg(dpopSigningAlg);
	} catch (e) {
		c.failureFrom("Failed to generate key for alg", e, { alg: dpopSigningAlg });
	}
	client.dpop.key = key;
	c.success("Generated dPOP JWKs", { private_jwk: key });
	return key;
}

/** upstream: condition/client/CreateDpopHeader.java */
export function createDpopHeader(client: DpopClient): Record<string, unknown> {
	const c: Condition = condition("CreateDpopHeader");
	// UPSTREAM: a missing key is a NullPointerException
	const jwk = client.dpop.key as JWK;
	let publicJwk;
	try {
		publicJwk = toPublicJWK(parseJWK(JSON.stringify(jwk)));
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Invalid DPoP JWK", e, { jwk });
		}
		throw e;
	}
	const header = { alg: jwk["alg"], typ: "dpop+jwt", jwk: publicJwk };
	c.success("Created DPoP proof header", header);
	return header;
}

/** upstream: condition/client/CreateDpopClaims.java */
export function createDpopClaims(): Record<string, unknown> {
	const claims: Record<string, unknown> = { jti: randomAlphanumeric(20), iat: Math.floor(Date.now() / 1000) };
	condition("CreateDpopClaims").success("Created DPoP proof claims", claims);
	return claims;
}

/** upstream: condition/client/SetDpopHtmHtuForTokenEndpoint.java */
export function setDpopHtmHtuForTokenEndpoint(claims: Record<string, unknown>, metadata: ServerMetadata): void {
	const c: Condition = condition("SetDpopHtmHtuForTokenEndpoint");
	const tokenEndpoint = metadata.token_endpoint;
	if (!tokenEndpoint) {
		c.failure("token_endpoint not found in server configuration", { server_config: metadata });
	}
	claims["htm"] = "POST";
	claims["htu"] = tokenEndpoint;
	c.success("Added htm/htu to DPoP proof claims", claims);
}

/** upstream: condition/client/SetDpopHtmHtuForParEndpoint.java */
export function setDpopHtmHtuForParEndpoint(
	claims: Record<string, unknown>,
	metadata: ServerMetadata,
	/** upstream "par_endpoint_http_method" (the modules that try other verbs); default POST */
	method = "POST",
): void {
	const c: Condition = condition("SetDpopHtmHtuForParEndpoint");
	const parEndpoint = metadata["pushed_authorization_request_endpoint"];
	if (typeof parEndpoint !== "string" || !parEndpoint) {
		c.failure("pushed_authorization_request_endpoint not found in server configuration", { server_config: metadata });
	}
	claims["htm"] = method;
	claims["htu"] = parEndpoint;
	c.success("Added htm/htu to DPoP proof claims", claims);
}

/** upstream: condition/client/SetDpopHtmHtuForResourceEndpoint.java */
export function setDpopHtmHtuForResourceEndpoint(
	claims: Record<string, unknown>,
	resource: { url: string; method?: string },
): void {
	claims["htm"] = resource.method || "GET";
	claims["htu"] = resource.url;
	condition("SetDpopHtmHtuForResourceEndpoint").success("Added htm/htu to DPoP proof claims", claims);
}

/** upstream: condition/client/SetDpopAccessTokenHash.java */
export function setDpopAccessTokenHash(claims: Record<string, unknown>, accessToken: AccessToken): void {
	// getBytes(US_ASCII): characters outside US-ASCII become '?'
	const ascii = Buffer.from(
		Array.from(accessToken.value, (ch) => (ch.charCodeAt(0) < 0x80 ? ch : "?")).join(""),
		"latin1",
	);
	claims["ath"] = createHash("sha256").update(ascii).digest("base64url");
	condition("SetDpopAccessTokenHash").success("Added ath to DPoP proof claims", {
		claims,
		access_token: accessToken.value,
	});
}

/** upstream: condition/client/SetDpopProofNonceForAuthorizationServer.java */
export function setDpopProofNonceForAuthorizationServer(claims: Record<string, unknown>, dpop: DpopState): void {
	const c: Condition = condition("SetDpopProofNonceForAuthorizationServer");
	const nonce = dpop.authorizationServerNonce;
	if (!nonce) {
		c.failure("authorization_server_dpop_nonce not found");
	}
	claims["nonce"] = nonce;
	c.success("Added nonce to DPoP proof claims", { "DPoP nonce": nonce });
}

/** upstream: condition/client/SetDpopProofNonceForResourceEndpoint.java */
export function setDpopProofNonceForResourceEndpoint(claims: Record<string, unknown>, dpop: DpopState): void {
	const c: Condition = condition("SetDpopProofNonceForResourceEndpoint");
	const nonce = dpop.resourceServerNonce;
	if (!nonce) {
		c.failure("resource_server_dpop_nonce not found");
	}
	claims["nonce"] = nonce;
	c.success("Added nonce to DPoP proof claims", { "DPoP nonce": nonce });
}

/**
 * NQCHAR = %x21 / %x23-5B / %x5D-7E: visible ASCII other than space, double-quote and backslash (RFC 6749 appendix
 * A, reused by RFC 9449 8.1 for the nonce); `1*NQCHAR` needs at least one character.
 *
 * upstream: condition/util/RFC6749AppendixASyntaxUtils.isNQCharSequence
 */
export function isNQCharSequence(value: string | null | undefined): boolean {
	return value != null && value !== "" && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(value);
}

/** upstream: condition/client/EnsureDpopNonceContainsAllowedCharactersOnly.java */
export function ensureDpopNonceContainsAllowedCharactersOnly(
	claims: Record<string, unknown>,
	...requirements: string[]
): void {
	const c: Condition = condition("EnsureDpopNonceContainsAllowedCharactersOnly", ...requirements);
	const dpopNonce = claims["nonce"];
	if (dpopNonce == null) {
		c.log("No DPOP nonce required");
		return;
	}
	if (!isNQCharSequence(String(dpopNonce))) {
		c.failure(
			"DPOP nonce contains illegal characters. As per RFC-6749, only NQCHAR characters %x21 / %x23-5B / %x5D-7E are allowed.",
			{ "DPOP nonce": dpopNonce },
		);
	}
	c.success("DPOP nonce does not contain any illegal characters", { "DPOP nonce": dpopNonce });
}

/** upstream: condition/client/SignDpopProof.java */
export async function signDpopProof(proof: DpopProof, client: DpopClient): Promise<string> {
	const c: Condition = condition("SignDpopProof");
	const jwk = client.dpop.key;
	if (jwk == null) {
		c.failure("No dpop_private_jwk found.");
	}
	try {
		const alg = proof.header["alg"];
		if (typeof alg !== "string") {
			// UPSTREAM: OIDFJSON.getString throws for anything but a string
			throw new TypeError("getString called on something that is not a string: " + JSON.stringify(alg));
		}
		const signingJwk = parseJWK(JSON.stringify(jwk));
		// JWSHeader.Builder(alg).customParams(headerClaims): alg from the builder, the header's own members as custom
		// parameters (alg among them, the same value)
		const header = { alg, ...proof.header };
		const signer = createJWSSigner(signingJwk, alg);
		const jws = await signer.sign(header as never, JSON.stringify(parseClaimsSet(proof.claims as never)));
		const publicJwk = toPublicJWK(signingJwk);
		c.success("Signed the DPoP proof", {
			dpop_proof: { verifiable_jws: jws, public_jwk: publicJwk != null ? JSON.stringify(publicJwk) : null },
			key: signingJwk,
		});
		return jws;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom(e.message, e);
		}
		if (e instanceof JOSEException) {
			c.failureFrom("Unable to sign dpop proof: " + String(e.cause ?? null), e);
		}
		throw e;
	}
}

/** upstream: condition/client/AddDpopHeaderForTokenEndpointRequest.java */
export function addDpopHeaderForTokenEndpointRequest(req: Pick<TokenRequest, "headers">, dpopProof: string): void {
	req.headers["DPoP"] = dpopProof;
	condition("AddDpopHeaderForTokenEndpointRequest").success("Set DPoP header", { DPoP: dpopProof });
}

/** upstream: condition/client/AddDpopHeaderForParEndpointRequest.java */
export function addDpopHeaderForParEndpointRequest(req: Pick<TokenRequest, "headers">, dpopProof: string): void {
	req.headers["DPoP"] = dpopProof;
	condition("AddDpopHeaderForParEndpointRequest").success("Set DPoP header for PAR endpoint", { DPoP: dpopProof });
}

/** upstream: condition/client/AddDpopHeaderForResourceEndpointRequest.java */
export function addDpopHeaderForResourceEndpointRequest(headers: Record<string, string>, dpopProof: string): void {
	headers["DPoP"] = dpopProof;
	condition("AddDpopHeaderForResourceEndpointRequest").success("Set DPoP header", { DPoP: dpopProof });
}

/**
 * The DPoP proof for a token endpoint request: header, claims (htm/htu of the token endpoint, the authorization
 * server's nonce when one is known), signed and set as the DPoP header.
 *
 * upstream: sequence/client/CreateDpopProofSteps.java (TOKEN) with condition/client/CreateDpopHeader.java,
 * CreateDpopClaims.java, SetDpopHtmHtuForTokenEndpoint.java, SetDpopProofNonceForAuthorizationServer.java,
 * EnsureDpopNonceContainsAllowedCharactersOnly.java, SignDpopProof.java, AddDpopHeaderForTokenEndpointRequest.java
 */
export async function createTokenEndpointDpopSteps(
	metadata: ServerMetadata,
	client: DpopClient,
	req: Pick<TokenRequest, "headers">,
): Promise<void> {
	const header = createDpopHeader(client);
	const claims = createDpopClaims();
	setDpopHtmHtuForTokenEndpoint(claims, metadata);
	soft(() => setDpopProofNonceForAuthorizationServer(claims, client.dpop), "info");
	soft(() => ensureDpopNonceContainsAllowedCharactersOnly(claims, "DPOP-8.1"));
	const proof = await signDpopProof({ header, claims }, client);
	addDpopHeaderForTokenEndpointRequest(req, proof);
}

/**
 * The DPoP proof for a PAR request (htm/htu of the PAR endpoint).
 *
 * upstream: sequence/client/CreateDpopProofSteps.java (PAR) with condition/client/SetDpopHtmHtuForParEndpoint.java,
 * AddDpopHeaderForParEndpointRequest.java
 */
export async function createParEndpointDpopSteps(
	metadata: ServerMetadata,
	client: DpopClient,
	req: Pick<TokenRequest, "headers">,
	method?: string,
): Promise<void> {
	const header = createDpopHeader(client);
	const claims = createDpopClaims();
	setDpopHtmHtuForParEndpoint(claims, metadata, method);
	soft(() => setDpopProofNonceForAuthorizationServer(claims, client.dpop), "info");
	soft(() => ensureDpopNonceContainsAllowedCharactersOnly(claims, "DPOP-8.1"));
	const proof = await signDpopProof({ header, claims }, client);
	addDpopHeaderForParEndpointRequest(req, proof);
}

/**
 * The DPoP proof for a resource request (htm/htu of the resource, the access token hash, the resource server's nonce
 * when one is known), set on the resource request headers.
 *
 * upstream: sequence/client/CreateDpopProofSteps.java (RESOURCE) with
 * condition/client/SetDpopHtmHtuForResourceEndpoint.java, SetDpopAccessTokenHash.java,
 * SetDpopProofNonceForResourceEndpoint.java, AddDpopHeaderForResourceEndpointRequest.java
 */
export async function createResourceEndpointDpopSteps(
	client: DpopClient,
	resource: { url: string; method?: string },
	accessToken: AccessToken,
	headers: Record<string, string>,
): Promise<void> {
	const header = createDpopHeader(client);
	const claims = createDpopClaims();
	setDpopHtmHtuForResourceEndpoint(claims, resource);
	setDpopAccessTokenHash(claims, accessToken);
	soft(() => setDpopProofNonceForResourceEndpoint(claims, client.dpop), "info");
	soft(() => ensureDpopNonceContainsAllowedCharactersOnly(claims, "DPOP-8.1"));
	const proof = await signDpopProof({ header, claims }, client);
	addDpopHeaderForResourceEndpointRequest(headers, proof);
}

/** upstream: condition/client/AddDpopJktToAuthorizationEndpointRequest.java */
export function addDpopJktToAuthorizationEndpointRequest(params: Record<string, unknown>, client: DpopClient): void {
	const c: Condition = condition("AddDpopJktToAuthorizationEndpointRequest");
	const key = client.dpop.key;
	if (key == null) {
		c.failure("DPOP key not found");
	}
	if (!Object.hasOwn(key, "kid")) {
		// 'kid' using thumbprint should have been created during key generation
		c.failure("DPOP key kid not available");
	}
	params["dpop_jkt"] = String(key["kid"]);
	c.success("Added dpop_jkt parameter to request", { ...params });
}

/** upstream: condition/client/AddInvalidDpopJktToAuthorizationEndpointRequest.java */
export function addInvalidDpopJktToAuthorizationEndpointRequest(
	params: Record<string, unknown>,
	client: DpopClient,
): void {
	const c: Condition = condition("AddInvalidDpopJktToAuthorizationEndpointRequest");
	const key = client.dpop.key;
	if (key == null) {
		c.failure("DPOP key not found");
	}
	if (!Object.hasOwn(key, "kid")) {
		// 'kid' using thumbprint should have been created during key generation
		c.failure("DPOP key kid not available");
	}
	const bytes = Buffer.from(String(key["kid"]), "base64url");
	// Flip some of the bits in the signature to make it invalid
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] ^= 0x5a;
	}
	params["dpop_jkt"] = bytes.toString("base64url");
	c.success("Added invalid dpop_jkt parameter to request", { ...params });
}

/**
 * The DPoP-Nonce response header, checked against RFC 9449: the nonce, or how the header breaks the RFC (the calling
 * condition raises the error), or neither when there is no header.
 *
 * upstream: util/http/DpopNonceResponseHeader.java
 */
export function dpopNonceResponseHeader(responseHeaders: Record<string, unknown> | null | undefined): {
	nonce: string | null;
	violation: string | null;
} {
	const header = responseHeaders?.["dpop-nonce"];
	if (header == null) {
		return { nonce: null, violation: null };
	}
	if (Array.isArray(header)) {
		return {
			nonce: null,
			violation: `The response contains ${header.length} DPoP-Nonce headers, but RFC9449 section 8 says there MUST NOT be more than one DPoP-Nonce header.`,
		};
	}
	if (typeof header !== "string") {
		return { nonce: null, violation: "The DPoP-Nonce response header could not be read as a string." };
	}
	if (header === "") {
		return {
			nonce: null,
			violation:
				"The DPoP-Nonce response header is empty, but RFC9449 section 8.1 defines the nonce as '1*NQCHAR', which requires at least one character.",
		};
	}
	if (!isNQCharSequence(header)) {
		return {
			nonce: null,
			violation:
				"The DPoP-Nonce response header contains characters that are not allowed. RFC9449 section 8.1 defines the nonce as '1*NQCHAR', so only the characters %x21 / %x23-5B / %x5D-7E may be used.",
		};
	}
	return { nonce: header, violation: null };
}

/** upstream: util/http/DpopNonceResponseHeader.describeSuppliedNonce */
export function describeSuppliedNonce(suppliedNonce: string | null): string {
	return suppliedNonce == null ? "no DPoP nonce supplied" : "DPoP nonce supplied";
}

/**
 * The challenges of a WWW-Authenticate header value: scheme -> parameters (quoted values unescaped, a trailing bare
 * token as a parameter without value).
 *
 * upstream: util/http/WwwAuthenticateHeaderValueParser.parse
 */
export function parseWwwAuthenticate(headerValue: string): Map<string, Map<string, string | null>> {
	const result = new Map<string, Map<string, string | null>>();
	for (const part of splitChallenges(headerValue)) {
		const [scheme, paramString = ""] = part.trim().split(/\s+(.*)/s, 2) as [string, string | undefined];
		const params = new Map<string, string | null>();
		if (paramString !== "") {
			const re = /([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*"((?:\\.|[^"\\])*)"|([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*([^",\s]+)/g;
			let lastMatchEnd = 0;
			for (const m of paramString.matchAll(re)) {
				if (m[1] != null) {
					params.set(m[1], m[2].replaceAll('\\"', '"').replaceAll("\\\\", "\\"));
				} else {
					params.set(m[3], m[4]);
				}
				lastMatchEnd = m.index + m[0].length;
			}
			if (lastMatchEnd < paramString.length) {
				let trailing = paramString.substring(lastMatchEnd).trim();
				if (trailing.startsWith(",")) {
					trailing = trailing.substring(1).trim();
				}
				if (trailing !== "" && /^[a-zA-Z][a-zA-Z0-9_-]*$/.test(trailing)) {
					params.set(trailing, null);
				}
			}
		}
		result.set(scheme, params);
	}
	return result;
}

/** upstream: util/http/WwwAuthenticateHeaderValueParser.splitChallenges */
function splitChallenges(header: string): string[] {
	const result: string[] = [];
	let current = "";
	let inQuotes = false;
	for (let i = 0; i < header.length; i++) {
		const c = header[i];
		if (c === '"') {
			inQuotes = !inQuotes || (i > 0 && header[i - 1] === "\\");
		} else if (c === "," && !inQuotes) {
			// Look ahead for scheme start
			let j = i + 1;
			while (j < header.length && /\s/.test(header[j])) {
				j++;
			}
			let k = j;
			while (k < header.length && /[a-zA-Z]/.test(header[k])) {
				k++;
			}
			if (k < header.length && header[k] === " ") {
				result.push(current);
				current = "";
				continue;
			}
		}
		current += c;
	}
	if (current !== "") {
		result.push(current);
	}
	return result;
}

/**
 * Whether the response carries a DPoP `use_dpop_nonce` challenge (RFC 9449 section 8/9), in one or several
 * WWW-Authenticate headers.
 *
 * upstream: util/http/WwwAuthenticateHeaderValueParser.hasUseDpopNonceChallenge
 */
export function hasUseDpopNonceChallenge(responseHeaders: Record<string, unknown> | null | undefined): boolean {
	const header = responseHeaders?.["www-authenticate"];
	if (header == null) {
		return false;
	}
	for (const value of Array.isArray(header) ? header : [header]) {
		if (typeof value !== "string") {
			continue;
		}
		for (const [scheme, params] of parseWwwAuthenticate(value)) {
			if (scheme.toLowerCase() === "dpop" && params.get("error") === "use_dpop_nonce") {
				return true;
			}
		}
	}
	return false;
}

/**
 * Calls the token endpoint and recognises a `use_dpop_nonce` error: the supplied DPoP-Nonce is kept for the retry
 * (`nonceError`, upstream "token_endpoint_dpop_nonce_error") and, as RFC 9449 8.2 allows the server to rotate the
 * nonce on any response, a nonce on a success is kept too.
 *
 * upstream: condition/client/CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse.java
 */
export async function callTokenEndpointAllowingDpopNonceError(
	op: { metadata: ServerMetadata },
	req: TokenRequest,
	dpop: DpopState,
	...requirements: string[]
): Promise<{ response: TokenResponse; nonceError: string | null }> {
	let nonceError: string | null = null;
	let suppliedDpopNonce: string | null = null;
	const response = await callTokenEndpoint(op, req, {
		conditionName: "CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse",
		requirements,
		onResponse: (c, res) => {
			const error = res.json?.["error"];
			// A DPoP-Nonce that breaks RFC9449 is reported whatever the status code was, so that the violation is
			// attributed to the response that carried it rather than to whatever we do with the value later on.
			const nonceHeader = dpopNonceResponseHeader(res.headers);
			if (nonceHeader.violation != null) {
				c.failure(nonceHeader.violation, { headers: res.headers });
			}
			suppliedDpopNonce = nonceHeader.nonce;
			if (res.status === 400 && error === "use_dpop_nonce") {
				if (nonceHeader.nonce == null) {
					c.failure(
						"The token endpoint returned a 'use_dpop_nonce' error but supplied no DPoP-Nonce header, leaving no nonce to retry the request with.",
						{ headers: res.headers },
					);
				}
				dpop.authorizationServerNonce = nonceHeader.nonce;
				nonceError = nonceHeader.nonce;
			} else if (res.status >= 200 && res.status < 300 && nonceHeader.nonce != null) {
				dpop.authorizationServerNonce = nonceHeader.nonce;
			}
		},
		parsedResponseLogSuffix: () => " - " + describeSuppliedNonce(suppliedDpopNonce),
	});
	return { response, nonceError };
}

/**
 * Calls the resource with the access token (and the DPoP header among `headers`) and recognises a
 * `use_dpop_nonce` challenge: a 401 with a DPoP challenge keeps the supplied nonce for the retry (`nonceError`,
 * upstream "resource_endpoint_dpop_nonce_error"); a nonce on a success replaces the stored one (RFC 9449 9).
 *
 * upstream: condition/client/CallProtectedResourceAllowingDpopNonceError.java
 */
export async function callProtectedResourceAllowingDpopNonceError(
	url: string,
	accessToken: AccessToken,
	dpop: DpopState,
	opts: { method?: "GET" | "POST"; headers?: Record<string, string>; requirements?: string[] } = {},
): Promise<{ response: EndpointResponse; nonceError: string | null }> {
	const name = "CallProtectedResourceAllowingDpopNonceError";
	const response = await callProtectedResource(url, accessToken, { ...opts, conditionName: name });
	const c: Condition = condition(name, ...(opts.requirements ?? []));
	// checked whatever the status code was, so the violation is attributed to the response that carried it
	const nonceHeader = dpopNonceResponseHeader(response.headers);
	if (nonceHeader.violation != null) {
		c.failure(nonceHeader.violation, { headers: response.headers });
	}
	let nonceError: string | null = null;
	if (response.status >= 200 && response.status < 300 && nonceHeader.nonce != null) {
		dpop.resourceServerNonce = nonceHeader.nonce;
	}
	if (response.status === 401 && hasUseDpopNonceChallenge(response.headers)) {
		if (nonceHeader.nonce == null) {
			c.failure(
				"The resource server returned a 'use_dpop_nonce' error but supplied no DPoP-Nonce header, leaving no nonce to retry the request with.",
				{ headers: response.headers },
			);
		}
		dpop.resourceServerNonce = nonceHeader.nonce;
		nonceError = nonceHeader.nonce;
	}
	return { response, nonceError };
}

/** upstream: condition/client/CheckTokenTypeIsDpop.java */
export function checkTokenTypeIsDpop(res: TokenResponse, ...requirements: string[]): void {
	const c: Condition = condition("CheckTokenTypeIsDpop", ...requirements);
	const tokenType = res.json?.["token_type"];
	if (typeof tokenType !== "string" || tokenType === "") {
		c.failure("Couldn't find token type");
	}
	if (tokenType.toLowerCase() !== "dpop") {
		c.failure("Token type is not DPoP");
	}
	c.success("Token type is DPoP");
}
