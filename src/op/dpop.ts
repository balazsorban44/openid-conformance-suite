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
import { parseClaimsSet, parseSignedJWT } from "../suite/jose-jwt.ts";
import { getString } from "../suite/json.ts";
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
export function addDpopHeaderForResourceEndpointRequest(headers: DpopRequestHeaders, dpopProof: string): void {
	headers["DPoP"] = dpopProof;
	condition("AddDpopHeaderForResourceEndpointRequest").success("Set DPoP header", { DPoP: dpopProof });
}

/** The request headers a DPoP proof is set on (several DPoP headers for the negative test that sends two) */
export type DpopRequestHeaders = Record<string, string | string[]>;

/**
 * What a module changes in a DPoP proof sequence (upstream: conditions inserted into / replacing the ones of
 * CreateDpopProofSteps, e.g. the invalid proofs of fapi2-security-profile-final-dpop-negative-tests or the iat
 * of the dpopproof-with-iat modules). Each hook names where upstream inserts the condition.
 */
export interface DpopProofSteps {
	/** inserted after CreateDpopClaims */
	afterClaims?: (claims: Record<string, unknown>) => void;
	/** replaces SetDpopHtmHtuFor<Endpoint> */
	htmHtu?: (claims: Record<string, unknown>) => void;
	/** inserted after SetDpopHtmHtuFor<Endpoint> (the header or the claims) */
	afterHtmHtu?: (proof: DpopProof) => void;
	/** resource endpoint: replaces SetDpopAccessTokenHash, or `.skip(SetDpopAccessTokenHash, reason)` when a string */
	ath?: ((claims: Record<string, unknown>) => void) | string;
	/** inserted before SignDpopProof */
	beforeSign?: (proof: DpopProof) => void | Promise<void>;
	/** replaces SignDpopProof */
	sign?: (proof: DpopProof) => string | Promise<string>;
	/** inserted after SignDpopProof: returns the (altered) proof */
	afterSign?: (proof: string) => string;
	/** replaces AddDpopHeaderFor<Endpoint>Request */
	addHeader?: (headers: DpopRequestHeaders, proof: string) => void | Promise<void>;
	/** inserted after AddDpopHeaderFor<Endpoint>Request */
	afterAddHeader?: (headers: DpopRequestHeaders) => void;
}

/** The proof's signing with the module's hooks around it (the tail of every CreateDpopProofSteps sequence) */
async function signAndAddDpopProof(
	proof: DpopProof,
	client: DpopClient,
	headers: DpopRequestHeaders,
	addHeader: (headers: DpopRequestHeaders, proof: string) => void,
	steps: DpopProofSteps,
): Promise<void> {
	await steps.beforeSign?.(proof);
	let signed = steps.sign ? await steps.sign(proof) : await signDpopProof(proof, client);
	if (steps.afterSign) {
		signed = steps.afterSign(signed);
	}
	if (steps.addHeader) {
		await steps.addHeader(headers, signed);
	} else {
		addHeader(headers, signed);
	}
	steps.afterAddHeader?.(headers);
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
	steps: DpopProofSteps = {},
): Promise<void> {
	const header = createDpopHeader(client);
	const claims = createDpopClaims();
	steps.afterClaims?.(claims);
	if (steps.htmHtu) {
		steps.htmHtu(claims);
	} else {
		setDpopHtmHtuForTokenEndpoint(claims, metadata);
	}
	steps.afterHtmHtu?.({ header, claims });
	soft(() => setDpopProofNonceForAuthorizationServer(claims, client.dpop), "info");
	soft(() => ensureDpopNonceContainsAllowedCharactersOnly(claims, "DPOP-8.1"));
	await signAndAddDpopProof(
		{ header, claims },
		client,
		req.headers,
		(_headers, proof) => addDpopHeaderForTokenEndpointRequest(req, proof),
		steps,
	);
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
	steps: DpopProofSteps = {},
): Promise<void> {
	const header = createDpopHeader(client);
	const claims = createDpopClaims();
	steps.afterClaims?.(claims);
	if (steps.htmHtu) {
		steps.htmHtu(claims);
	} else {
		setDpopHtmHtuForParEndpoint(claims, metadata, method);
	}
	steps.afterHtmHtu?.({ header, claims });
	soft(() => setDpopProofNonceForAuthorizationServer(claims, client.dpop), "info");
	soft(() => ensureDpopNonceContainsAllowedCharactersOnly(claims, "DPOP-8.1"));
	await signAndAddDpopProof(
		{ header, claims },
		client,
		req.headers,
		(_headers, proof) => addDpopHeaderForParEndpointRequest(req, proof),
		steps,
	);
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
	headers: DpopRequestHeaders,
	steps: DpopProofSteps = {},
): Promise<void> {
	const header = createDpopHeader(client);
	const claims = createDpopClaims();
	steps.afterClaims?.(claims);
	if (steps.htmHtu) {
		steps.htmHtu(claims);
	} else {
		setDpopHtmHtuForResourceEndpoint(claims, resource);
	}
	steps.afterHtmHtu?.({ header, claims });
	if (typeof steps.ath === "string") {
		condition("SetDpopAccessTokenHash").log(steps.ath);
	} else if (steps.ath) {
		steps.ath(claims);
	} else {
		setDpopAccessTokenHash(claims, accessToken);
	}
	soft(() => setDpopProofNonceForResourceEndpoint(claims, client.dpop), "info");
	soft(() => ensureDpopNonceContainsAllowedCharactersOnly(claims, "DPOP-8.1"));
	await signAndAddDpopProof({ header, claims }, client, headers, addDpopHeaderForResourceEndpointRequest, steps);
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
	opts: { method?: "GET" | "POST"; headers?: DpopRequestHeaders; requirements?: string[] } = {},
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

// ---- the claims the modules change in a proof ----

const now = () => Math.floor(Date.now() / 1000);

/** upstream: condition/client/SetDpopNbfToNow.java */
export function setDpopNbfToNow(claims: Record<string, unknown>): void {
	claims["nbf"] = now();
	condition("SetDpopNbfToNow").success("Set 'nbf' in DPoP proof to now", claims);
}

/** upstream: condition/client/SetDpopExpToFiveMinutesInFuture.java */
export function setDpopExpToFiveMinutesInFuture(claims: Record<string, unknown>): void {
	claims["exp"] = now() + 5 * 60;
	condition("SetDpopExpToFiveMinutesInFuture").success("Set 'exp' in DPoP proof to 5 minutes in the future", claims);
}

/** upstream: condition/client/SetDpopIatTo10SecondsInPast.java */
export function setDpopIatTo10SecondsInPast(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["iat"] = now() - 10;
	condition("SetDpopIatTo10SecondsInPast", ...requirements).success(
		"Set DPoP proof 'iat' claim to 10 seconds in the past",
		claims,
	);
}

/**
 * This condition is meant to test for 10 seconds but set to 8 to allow for network latency
 *
 * upstream: condition/client/SetDpopIatTo8SecondsInFuture.java
 */
export function setDpopIatTo8SecondsInFuture(claims: Record<string, unknown>, ...requirements: string[]): void {
	claims["iat"] = now() + 8;
	// UPSTREAM: the message says 10 seconds
	condition("SetDpopIatTo8SecondsInFuture", ...requirements).success(
		"Set DPoP proof 'iat' claim to 10 seconds in the future",
		claims,
	);
}

/** upstream: condition/client/SetDpopIatToOneHourInFuture.java */
export function setDpopIatToOneHourInFuture(claims: Record<string, unknown>): void {
	claims["iat"] = now() + 60 * 60;
	condition("SetDpopIatToOneHourInFuture").success("Set 'iat' in DPoP proof to one hour in future", claims);
}

/** upstream: condition/client/SetDpopIatToOneHourInPast.java */
export function setDpopIatToOneHourInPast(claims: Record<string, unknown>): void {
	claims["iat"] = now() - 60 * 60;
	condition("SetDpopIatToOneHourInPast").success("Set 'iat' in DPoP proof to one hour in past", claims);
}

/** upstream: condition/client/SetDpopAccessTokenHashToIncorrectValue.java */
export function setDpopAccessTokenHashToIncorrectValue(claims: Record<string, unknown>): void {
	const accessToken = randomAlphanumeric(10);
	claims["ath"] = createHash("sha256").update(Buffer.from(accessToken, "latin1")).digest("base64url");
	condition("SetDpopAccessTokenHashToIncorrectValue").success("Added ath to DPoP proof claims", {
		claims,
		bad_access_token: accessToken,
	});
}

/** upstream: condition/client/SetDpopHeaderJwkToPrivateKey.java */
export function setDpopHeaderJwkToPrivateKey(proof: DpopProof, client: DpopClient): void {
	// UPSTREAM: a missing key is a NullPointerException
	proof.header["jwk"] = client.dpop.key as JWK;
	condition("SetDpopHeaderJwkToPrivateKey").success("Added private jwk to DPoP proof header", proof.header);
}

// ---- the invalid proofs of fapi2-security-profile-final-dpop-negative-tests (condition/client/Fapi2DPoPNegativeConditions.java) ----

/** upstream: Fapi2DPoPNegativeConditions.ChangeDpopHeader (the header after the change) */
function changeDpopHeader(name: string, header: Record<string, unknown>, change: () => void): void {
	change();
	condition(name).success("DPoP proof header", header);
}

/** upstream: Fapi2DPoPNegativeConditions.ChangeDpopClaims (the claims after the change) */
function changeDpopClaims(name: string, claims: Record<string, unknown>, change: () => void): void {
	change();
	condition(name).success("DPoP proof claims", claims);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveTypFromDpopProof) */
export function removeTypFromDpopProof(header: Record<string, unknown>): void {
	changeDpopHeader("RemoveTypFromDpopProof", header, () => delete header["typ"]);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveJwkFromDpopProof) */
export function removeJwkFromDpopProof(header: Record<string, unknown>): void {
	changeDpopHeader("RemoveJwkFromDpopProof", header, () => delete header["jwk"]);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (SetDpopHeaderTypToInvalidValue) */
export function setDpopHeaderTypToInvalidValue(header: Record<string, unknown>): void {
	changeDpopHeader("SetDpopHeaderTypToInvalidValue", header, () => {
		header["typ"] = "dpop+jwt+wrongyousee";
	});
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (AddExtraClaimsToHeader) */
export function addExtraClaimsToHeader(header: Record<string, unknown>): void {
	changeDpopHeader("AddExtraClaimsToHeader", header, () => {
		header["tx_id"] = now() + 60 * 60;
	});
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (ChangeSignAlgorithm) */
export function changeSignAlgorithm(header: Record<string, unknown>): void {
	changeDpopHeader("ChangeSignAlgorithm", header, () => {
		delete header["alg"];
		header["alg"] = "RS256";
	});
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveJtiFromDpopProof) */
export function removeJtiFromDpopProof(claims: Record<string, unknown>): void {
	changeDpopClaims("RemoveJtiFromDpopProof", claims, () => delete claims["jti"]);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveHtmFromDpopProof) */
export function removeHtmFromDpopProof(claims: Record<string, unknown>): void {
	changeDpopClaims("RemoveHtmFromDpopProof", claims, () => delete claims["htm"]);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveHtuFromDpopProof) */
export function removeHtuFromDpopProof(claims: Record<string, unknown>): void {
	changeDpopClaims("RemoveHtuFromDpopProof", claims, () => delete claims["htu"]);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveIatFromDpopProof) */
export function removeIatFromDpopProof(claims: Record<string, unknown>): void {
	changeDpopClaims("RemoveIatFromDpopProof", claims, () => delete claims["iat"]);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (AddExtraClaimsToClaims) */
export function addExtraClaimsToClaims(claims: Record<string, unknown>): void {
	changeDpopClaims("AddExtraClaimsToClaims", claims, () => {
		claims["tx_id_key"] = now() + 60 * 60;
	});
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (SetDpopHtmToPut) */
export function setDpopHtmToPut(claims: Record<string, unknown>): void {
	changeDpopClaims("SetDpopHtmToPut", claims, () => {
		claims["htm"] = "PUT";
	});
}

/**
 * The same jti for every proof of the module's reuse test (upstream env "jti": created on the first use, cleared
 * for a nonce retry).
 *
 * upstream: condition/client/Fapi2DPoPNegativeConditions.java (FixedJtiClaim)
 */
export function fixedJtiClaim(claims: Record<string, unknown>, state: { jti: string | null }): void {
	changeDpopClaims("FixedJtiClaim", claims, () => {
		if (!state.jti) {
			state.jti = randomAlphanumeric(15);
		}
		claims["jti"] = state.jti;
	});
}

/**
 * The resource URL with the scheme and host in upper case as htu (RFC 3986 6.2.2.1: case-insensitive).
 *
 * upstream: condition/client/Fapi2DPoPNegativeConditions.java (DpopHtuUpperCase)
 */
export function dpopHtuUpperCase(claims: Record<string, unknown>, resource: { url: string; method?: string }): void {
	changeDpopClaims("DpopHtuUpperCase", claims, () => {
		const resourceEndpoint = resource.url;
		claims["htm"] = resource.method || "GET";
		const resourceURI = new URL(resourceEndpoint);
		// java.net.URI.getHost / getScheme: the host as given (no brackets for IPv6 here), the scheme without ':'
		const host = resourceURI.hostname;
		const scheme = resourceURI.protocol.slice(0, -1);
		const changedResourceEndoint = resourceEndpoint
			.replace(host, host.toUpperCase())
			.replace(scheme, scheme.toUpperCase());
		claims["htu"] = changedResourceEndoint;
		condition("DpopHtuUpperCase").success("Added htm/htu to DPoP proof claims", claims);
	});
}

/**
 * The resource URL with the scheme's default port spelled out as htu (RFC 3986 6.2.3).
 *
 * upstream: condition/client/Fapi2DPoPNegativeConditions.java (DpopHtuWithPort)
 */
export function dpopHtuWithPort(claims: Record<string, unknown>, resource: { url: string; method?: string }): void {
	changeDpopClaims("DpopHtuWithPort", claims, () => {
		const c: Condition = condition("DpopHtuWithPort");
		let resourceEndpoint = resource.url;
		let uri: URL;
		try {
			uri = new URL(resourceEndpoint);
		} catch (e) {
			c.failureFrom((e as Error).message, e);
		}
		if (uri.port === "") {
			const scheme = uri.protocol.slice(0, -1);
			resourceEndpoint = scheme + "://" + uri.hostname + (scheme === "https" ? ":443" : ":80") + uri.pathname;
		}
		claims["htm"] = resource.method || "GET";
		claims["htu"] = resourceEndpoint;
	});
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (AddDpopHeaderAllCapital) */
export function addDpopHeaderAllCapital(headers: DpopRequestHeaders, dpopProof: string): void {
	headers["DPOP"] = dpopProof;
	condition("AddDpopHeaderAllCapital").success("Set DPoP header", { DPOP: dpopProof });
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveDpopFromResourceRequest) */
export function removeDpopFromResourceRequest(headers: DpopRequestHeaders): void {
	delete headers["DPoP"];
	condition("RemoveDpopFromResourceRequest").success("Removed DPoP from resource header", { ...headers });
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (SignDpopProofWithNone) */
export function signDpopProofWithNone(claims: Record<string, unknown>): string {
	const ALG_NONE_HEADER = '{"alg": "none", "typ": "dpop+jwt"}';
	const jwt =
		Buffer.from(ALG_NONE_HEADER).toString("base64url") +
		"." +
		Buffer.from(JSON.stringify(claims)).toString("base64url") +
		".";
	condition("SignDpopProofWithNone").success("Signed the DPoP proof with none alg", { dpop_proof: jwt });
	return jwt;
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (InvalidateDpopProofSignature; common/AbstractInvalidateJwsSignature) */
export function invalidateDpopProofSignature(dpopProof: string): string {
	const c: Condition = condition("InvalidateDpopProofSignature");
	let parsed;
	try {
		parsed = parseSignedJWT(dpopProof);
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Couldn't parse JWT", e, { dpop_proof: dpopProof });
		}
		throw e;
	}
	const bytes = Buffer.from(parsed.signature ?? "", "base64url");
	// Flip some of the bits in the signature to make it invalid
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] ^= 0x5a;
	}
	const invalid = parsed.parts[0] + "." + parsed.parts[1] + "." + bytes.toString("base64url");
	c.log("Made the dpop_proof signature invalid", { dpop_proof: invalid });
	return invalid;
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (NotWellformedDPoP): the proof without its signature part */
export function notWellformedDPoP(dpopProof: string): string {
	const parts = dpopProof.split(".");
	const jws = parts[0] + "." + parts[1];
	condition("NotWellformedDPoP").success("Changed the DPoP proof", { dpop_proof: jws });
	return jws;
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (SignDpopAndRemoveAlg): "alg" renamed in the signed header */
export function signDpopAndRemoveAlg(dpopProof: string): string {
	const parts = dpopProof.split(".");
	parts[0] = Buffer.from(Buffer.from(parts[0], "base64url").toString().replace("alg", "alg2")).toString("base64url");
	const jws = parts.join(".");
	condition("SignDpopAndRemoveAlg").success("Changed the DPoP proof", { dpop_proof: jws });
	return jws;
}

/**
 * Replaces the client's DPoP key with a new one of the same algorithm (the old one kept for RecoverSignKey).
 *
 * upstream: condition/client/Fapi2DPoPNegativeConditions.java (GenerateNewSignKey; AbstractGenerateKey)
 */
export async function generateNewSignKey(client: DpopClient & { dpopKeyOld?: JWK | null }): Promise<void> {
	const c: Condition = condition("GenerateNewSignKey");
	const jwk = client.dpop.key as JWK;
	let signingJwk;
	try {
		signingJwk = parseJWK(JSON.stringify(jwk));
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom(e.message, e);
		}
		throw e;
	}
	const dpopSigningAlg = String(signingJwk["alg"]);
	// a new key, distinct from the existing dpop_private_jwk. This is the test's whole point.
	let key: JWK;
	try {
		key = await generateJwkForAlg(dpopSigningAlg);
	} catch {
		c.failure("Failed to generate key for alg", { alg: dpopSigningAlg });
	}
	// AbstractGenerateKey adds no kid (GenerateDpopKey does)
	delete key["kid"];
	client.dpop.key = key;
	client.dpopKeyOld = jwk;
	// upstream logs nothing: the framework notes that the condition ran
	c.log("Condition ran but did not log anything");
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RecoverSignKey) */
export function recoverSignKey(client: DpopClient & { dpopKeyOld?: JWK | null }): void {
	client.dpop.key = client.dpopKeyOld ?? null;
	condition("RecoverSignKey").log("Condition ran but did not log anything");
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RenameDPoPProof): the proof kept as "dpop_proof2" */
export function renameDPoPProof(dpopProof: string): string {
	condition("RenameDPoPProof").log("Condition ran but did not log anything");
	return dpopProof;
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (AddMultipleDpopHeaderForResourceEndpointRequest) */
export function addMultipleDpopHeaderForResourceEndpointRequest(
	headers: DpopRequestHeaders,
	dpopProof: string,
	dpopProof2: string,
): void {
	// UPSTREAM: removes "DPOP", not the "DPoP" the sequence set
	delete headers["DPOP"];
	const element = [dpopProof, dpopProof2];
	headers["DPoP"] = element;
	condition("AddMultipleDpopHeaderForResourceEndpointRequest").success("Set DPoP header", { DPoP: element });
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (RemoveQueryAndFragmentFromDpopHtu) */
export function removeQueryAndFragmentFromDpopHtu(claims: Record<string, unknown>): void {
	const c: Condition = condition("RemoveQueryAndFragmentFromDpopHtu");
	let htu = getString(claims["htu"]);
	const lastIndexOf = htu.lastIndexOf("?");
	if (lastIndexOf > 0) {
		htu = htu.substring(0, lastIndexOf);
	}
	claims["htu"] = htu;
	c.success(
		"Remove query/fragment (which must be ignored as per 4.3-9 in DPoP spec) to htu in DPoP proof claims",
		claims,
	);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (AddQueryAndFragmentToDpopHtu) */
export function addQueryAndFragmentToDpopHtu(claims: Record<string, unknown>): void {
	const c: Condition = condition("AddQueryAndFragmentToDpopHtu");
	let htu = getString(claims["htu"]);
	if (htu.lastIndexOf("?") === -1) {
		htu = htu + "?allthedoorsonthisspaceshiphavebeen#programmedtohaveacheeryandsunnydisposition";
	}
	claims["htu"] = htu;
	c.success(
		"Added query/fragment (which must be ignored as per 4.3-9 in DPoP spec) to htu in DPoP proof claims",
		claims,
	);
}

/** upstream: condition/client/Fapi2DPoPNegativeConditions.java (SetDpopHtuToDifferentUrl) */
export function setDpopHtuToDifferentUrl(claims: Record<string, unknown>): void {
	const c: Condition = condition("SetDpopHtuToDifferentUrl");
	let htu = getString(claims["htu"]);
	const lastIndexOf = htu.lastIndexOf("?");
	htu = lastIndexOf > 0 ? htu.substring(0, lastIndexOf) + "ohnonotagain" : htu + "ohnonotagain";
	claims["htu"] = htu;
	c.success("Made htu in DPoP proof claims a different url", claims);
}

/**
 * Calls the resource with the access token presented as a Bearer token whatever its type (the request headers,
 * without a DPoP proof, as they are).
 *
 * upstream: condition/client/CallProtectedResourceForceBearer.java
 */
export function callProtectedResourceForceBearer(
	resource: { url: string; method?: string },
	accessToken: AccessToken,
	headers: DpopRequestHeaders,
	...requirements: string[]
): Promise<EndpointResponse> {
	return callProtectedResource(
		resource.url,
		{ ...accessToken, type: "Bearer" },
		{
			method: resource.method as "GET" | "POST" | undefined,
			headers,
			requirements,
			conditionName: "CallProtectedResourceForceBearer",
		},
	);
}
