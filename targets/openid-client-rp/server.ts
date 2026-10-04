/**
 * Relying Party under test for the RP (oidcc-client-*) plans, built on panva's openid-client v6. It replaces
 * upstream's gitlab.com/openid/sample-openid-client-nodejs (openid-client v3, launched per module by
 * scripts/run-test-plan.py with ISSUER / VARIANT / MODULE_NAME / CLIENT_METADATA_DEFAULTS env vars) with a long
 * running HTTP server that the runner drives with one request per test module. See README.md for the contract.
 *
 *   node targets/openid-client-rp/server.ts
 *
 * Environment:
 *   PORT (4000)                       http listener; RP_BASE_URL (http://localhost:PORT) is how others reach it
 *   RP_HTTPS_PORT (4443)              https listener (configs/certs/localhost.{crt,key}) for initiate_login_uri and
 *                                     request objects, 0 disables (the configs pass free ports: ${PORT}, ${PORT_HTTPS})
 *   RP_STATIC_CLIENT_ID / RP_STATIC_CLIENT_SECRET   static client defaults (openid-client-rp / rp-secret-...)
 *   RP_JWKS                           private JWKS JSON to use instead of keys generated at startup
 *   RP_CHROMIUM_EXECUTABLE_PATH       chromium binary for the Playwright user agent (default: Playwright's)
 *   RP_LOGIN_TIMEOUT_MS (30000)       how long to wait for an authorization round trip
 *   DEBUG_RP=1                        verbose logging
 */
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { fileURLToPath } from "node:url";
import * as client from "openid-client";
import * as jose from "jose";

// ---------------------------------------------------------------------------------------------------------------
// configuration

const PORT = Number(process.env["PORT"] ?? 4000);
const BASE = (process.env["RP_BASE_URL"] ?? `http://localhost:${PORT}`).replace(/\/$/, "");
const HTTPS_PORT = Number(process.env["RP_HTTPS_PORT"] ?? 4443);
const HTTPS_BASE = (process.env["RP_HTTPS_BASE_URL"] ?? `https://localhost:${HTTPS_PORT}`).replace(/\/$/, "");
const STATIC_CLIENT_ID = process.env["RP_STATIC_CLIENT_ID"] ?? "openid-client-rp";
const STATIC_CLIENT_SECRET = process.env["RP_STATIC_CLIENT_SECRET"] ?? "rp-secret-0123456789abcdefghij";
const LOGIN_TIMEOUT_MS = Number(process.env["RP_LOGIN_TIMEOUT_MS"] ?? 30_000);
const DEBUG = process.env["DEBUG_RP"] === "1";
/** certificate of the https listener (initiate_login_uri must be https, ValidateClientInitiateLoginUri) */
const CERTS = new URL("../../configs/certs/", import.meta.url);

const REDIRECT_URI = `${BASE}/cb`;
const POST_LOGOUT_REDIRECT_URI = `${BASE}/logged-out`;
const BACKCHANNEL_LOGOUT_URI = `${BASE}/backchannel-logout`;
const FRONTCHANNEL_LOGOUT_URI = `${BASE}/frontchannel-logout`;
const INITIATE_LOGIN_URI = `${HTTPS_BASE}/initiate-login`;
/** request_uri values are https when the https listener is on (required when the request object is unsigned) */
const REQUEST_OBJECT_BASE = `${HTTPS_PORT ? HTTPS_BASE : BASE}/request-object/`;
const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

// ---------------------------------------------------------------------------------------------------------------
// keys: one signing key per family (private_key_jwt, request objects) and encryption keys (id_token / userinfo
// encryption), published inline as `jwks` in the registration request like the upstream sample client does

interface RpKeys {
	rsaSig: jose.JWK;
	ecSig: jose.JWK;
	edSig: jose.JWK;
	rsaEnc: jose.JWK;
	ecEnc: jose.JWK;
}

let KEYS: RpKeys;
let PUBLIC_JWKS: { keys: jose.JWK[] };

async function generateKey(alg: string, use: string, options: jose.GenerateKeyPairOptions = {}): Promise<jose.JWK> {
	const { privateKey } = await jose.generateKeyPair(alg, { ...options, extractable: true });
	const jwk = { ...(await jose.exportJWK(privateKey)), use };
	return { ...jwk, kid: await jose.calculateJwkThumbprint(jwk) };
}

async function initKeys(): Promise<void> {
	if (process.env["RP_JWKS"]) {
		const { keys } = JSON.parse(process.env["RP_JWKS"]) as { keys: jose.JWK[] };
		const find = (pred: (k: jose.JWK) => boolean, what: string) => {
			const k = keys.find(pred);
			if (!k) {
				throw new Error(`RP_JWKS has no ${what} key`);
			}
			return k;
		};
		KEYS = {
			rsaSig: find((k) => k.kty === "RSA" && k.use !== "enc", "RSA sig"),
			ecSig: find((k) => k.kty === "EC" && k.use !== "enc", "EC sig"),
			edSig: find((k) => k.kty === "OKP" && k.crv === "Ed25519", "Ed25519"),
			rsaEnc: find((k) => k.kty === "RSA" && k.use === "enc", "RSA enc"),
			ecEnc: find((k) => k.kty === "EC" && k.use === "enc", "EC enc"),
		};
	} else {
		KEYS = {
			rsaSig: await generateKey("RS256", "sig", { modulusLength: 2048 }),
			ecSig: await generateKey("ES256", "sig"),
			edSig: await generateKey("Ed25519", "sig"),
			rsaEnc: await generateKey("RSA-OAEP", "enc", { modulusLength: 2048 }),
			ecEnc: await generateKey("ECDH-ES", "enc", { crv: "P-256" }),
		};
	}
	PUBLIC_JWKS = { keys: Object.values(KEYS).map(({ d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub }) => pub) };
}

async function importKey(jwk: jose.JWK, alg: string): Promise<client.CryptoKey> {
	const { use: _use, alg: _alg, key_ops: _ops, ...material } = jwk;
	return (await jose.importJWK(material, alg)) as client.CryptoKey;
}

/** private signing key for a JWS alg (private_key_jwt assertions, request objects) */
async function signingKey(alg: string, jwks?: { keys: jose.JWK[] }): Promise<client.PrivateKey> {
	let jwk: jose.JWK | undefined;
	if (jwks) {
		const kty = alg.startsWith("ES") ? "EC" : alg.startsWith("RS") || alg.startsWith("PS") ? "RSA" : "OKP";
		jwk = jwks.keys.find((k) => k.d && k.use !== "enc" && k.kty === kty);
		if (!jwk) {
			throw new Error(`static client jwks has no private ${kty} key for ${alg}`);
		}
	} else if (alg.startsWith("RS") || alg.startsWith("PS")) {
		jwk = KEYS.rsaSig;
	} else if (alg === "ES256") {
		jwk = KEYS.ecSig;
	} else if (alg === "EdDSA" || alg === "Ed25519") {
		jwk = KEYS.edSig;
	} else {
		throw new Error(`no RP signing key for alg ${alg}`);
	}
	return { key: await importKey(jwk, alg), kid: jwk.kid };
}

/** decryption keys for the registered id_token / userinfo encryption algs */
async function decryptionKeys(algs: string[]): Promise<client.DecryptionKey[]> {
	const keys: client.DecryptionKey[] = [];
	for (const alg of new Set(algs)) {
		// symmetric key management (A128KW, dir, ...) is not supported by openid-client v6
		const jwk = alg.startsWith("RSA-OAEP") ? KEYS.rsaEnc : alg.startsWith("ECDH-ES") ? KEYS.ecEnc : undefined;
		if (jwk) {
			keys.push({ key: await importKey(jwk, alg), alg, kid: jwk.kid });
		}
	}
	return keys;
}

// ---------------------------------------------------------------------------------------------------------------
// small helpers

/** Promise.withResolvers whose rejection never counts as unhandled (it may be awaited late, or not at all) */
function deferred<T>(): PromiseWithResolvers<T> {
	const d = Promise.withResolvers<T>();
	d.promise.catch(() => {});
	return d;
}

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
	let timer: NodeJS.Timeout | undefined;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms waiting for ${what}`)), ms);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function describeError(err: unknown): string {
	if (!(err instanceof Error)) {
		return String(err);
	}
	const { code, error, error_description } = err as { code?: string; error?: string; error_description?: string };
	const parts = [`${err.name}: ${err.message}`];
	if (code) {
		parts.push(`(${code})`);
	}
	if (error) {
		parts.push(`[${error}${error_description ? `: ${error_description}` : ""}]`);
	}
	if (err.cause instanceof URLSearchParams && err.cause.get("error")) {
		parts.push(`[${err.cause.get("error")}: ${err.cause.get("error_description") ?? ""}]`);
	}
	return parts.join(" ");
}

const norm = (issuer: string) => issuer.replace(/\/$/, "");

function htmlSafe(value: unknown): string {
	return String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

const jsString = (value: unknown) => JSON.stringify(value).replace(/</g, "\\u003c");

function page(title: string, body: string, head = ""): string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${htmlSafe(title)}</title>${head}</head><body>${body}</body></html>`;
}

function hashAlgForJws(alg: string): string {
	if (alg === "EdDSA" || alg === "Ed25519") {
		return "SHA-512";
	}
	const bits = alg.slice(-3);
	if (bits === "256" || bits === "384" || bits === "512") {
		return `SHA-${bits}`;
	}
	throw new Error(`unsupported JWS algorithm for hash calculation: ${alg}`);
}

/** OIDC Core 3.2.2.9 / 3.3.2.11: at_hash in a front-channel ID Token issued together with an access_token */
async function validateAtHash(idToken: string, accessToken: string): Promise<void> {
	const { alg } = jose.decodeProtectedHeader(idToken);
	const claims = jose.decodeJwt(idToken);
	if (typeof claims["at_hash"] !== "string") {
		throw new Error("missing required property at_hash");
	}
	const digest = new Uint8Array(
		await crypto.subtle.digest(hashAlgForJws(String(alg)), new TextEncoder().encode(accessToken)),
	);
	const expected = Buffer.from(digest.slice(0, digest.length / 2)).toString("base64url");
	if (claims["at_hash"] !== expected) {
		throw new Error(`at_hash mismatch, expected ${expected}, got: ${claims["at_hash"]}`);
	}
}

// ---------------------------------------------------------------------------------------------------------------
// per test module behaviour (mirrors sample-openid-client-nodejs/modules/*.js, plus the logout / config modules
// the sample client never implemented)

type Kind =
	| "login"
	| "discovery"
	| "jwks"
	| "webfinger-acct"
	| "webfinger-url"
	| "issuer-mismatch"
	| "register"
	| "refresh"
	| "key-rotation"
	| "3rd-party"
	| "rp-logout"
	| "op-frontchannel-logout"
	| "session-management";

interface ModuleSpec {
	kind: Kind;
	/** the module is a negative test: the RP is expected to reject the (login / refresh) response */
	expectFailure?: boolean;
	/** extra authorization request parameters */
	params?: Record<string, string>;
	/** extra client metadata for registration */
	metadata?: Record<string, unknown>;
	/** overrides the request_type variant */
	requestType?: string;
	userinfoVia?: "header" | "body";
	skipUserinfo?: boolean;
	/** extra assertion on the login result */
	check?: (r: LoginResult) => void;
	/** backchannel logout modules: whether the RP must accept the logout_token */
	backchannel?: "accept" | "reject";
}

/** a normal login whose response the RP must reject */
const REJECT: ModuleSpec = { kind: "login", expectFailure: true };
const RP_LOGOUT: ModuleSpec = { kind: "rp-logout" };

/** a login with scope=openid email whose result must carry a claim */
function emailScope(has: (r: LoginResult) => boolean, missing: string): ModuleSpec {
	return {
		kind: "login",
		params: { scope: "openid email" },
		check: (r) => {
			if (!has(r)) {
				throw new Error(missing);
			}
		},
	};
}

/** module name without the "oidcc-client-test-" prefix -> behaviour; not listed: a normal login (moduleSpec) */
const MODULES: Record<string, ModuleSpec> = {
	"invalid-iss": REJECT,
	"missing-sub": REJECT,
	"invalid-aud": REJECT,
	"missing-aud": REJECT,
	"missing-iat": REJECT,
	"kid-absent-multiple-jwks": REJECT,
	"userinfo-invalid-sub": REJECT,
	"nonce-invalid": REJECT,
	"missing-chash": REJECT,
	"invalid-chash": REJECT,
	"missing-athash": REJECT,
	"invalid-athash": REJECT,
	"form-post-error": { kind: "login", params: { max_age: "0", prompt: "none" }, expectFailure: true },
	"scope-userinfo-claims": emailScope(
		(r) => !!(r.accessToken ? r.userinfo?.["email"] : r.claims?.["email"]),
		"email claim missing",
	),
	"aggregated-claims": emailScope((r) => !!r.userinfo?.["address"], "aggregated address claim missing"),
	"distributed-claims": emailScope(
		(r) => r.userinfo?.["credit_score"] !== undefined,
		"distributed credit_score claim missing",
	),
	"client-secret-basic": { kind: "login", metadata: { token_endpoint_auth_method: "client_secret_basic" } },
	"idtoken-sig-none": { kind: "login", metadata: { id_token_signed_response_alg: "none" } },
	"idtoken-sig-rs256": { kind: "login", metadata: { id_token_signed_response_alg: "RS256" } },
	"invalid-sig-es256": { kind: "login", metadata: { id_token_signed_response_alg: "ES256" }, expectFailure: true },
	"invalid-sig-hs256": { kind: "login", metadata: { id_token_signed_response_alg: "HS256" }, expectFailure: true },
	"invalid-sig-rs256": { kind: "login", metadata: { id_token_signed_response_alg: "RS256" }, expectFailure: true },
	"userinfo-bearer-body": { kind: "login", userinfoVia: "body" },
	"userinfo-bearer-header": { kind: "login", userinfoVia: "header" },
	"request-uri-signed-none": {
		kind: "login",
		requestType: "request_uri",
		metadata: { request_object_signing_alg: "none" },
	},
	"request-uri-signed-rs256": {
		kind: "login",
		requestType: "request_uri",
		metadata: { request_object_signing_alg: "RS256" },
	},
	"refresh-token": { kind: "refresh", skipUserinfo: true },
	"refresh-token-invalid-issuer": { kind: "refresh", skipUserinfo: true, expectFailure: true },
	"refresh-token-invalid-sub": { kind: "refresh", skipUserinfo: true, expectFailure: true },
	"discovery-openid-config": { kind: "discovery" },
	"discovery-jwks-uri-keys": { kind: "jwks" },
	"discovery-webfinger-acct": { kind: "webfinger-acct" },
	"discovery-webfinger-url": { kind: "webfinger-url" },
	"discovery-issuer-mismatch": { kind: "issuer-mismatch", expectFailure: true },
	"dynamic-registration": { kind: "register" },
	"signing-key-rotation": { kind: "key-rotation" },
	// a single login: the id_token is signed with a key the cached JWKS does not contain, openid-client refetches
	"signing-key-rotation-just-before-signing": { kind: "login" },
	"3rd-party-init-login": { kind: "3rd-party" },
	"rp-init-logout": RP_LOGOUT,
	"rp-init-logout-other-state": RP_LOGOUT,
	"rp-init-logout-no-state": RP_LOGOUT,
	"rp-frontchannel-rpinitlogout": RP_LOGOUT,
	"rp-backchannel-rpinitlogout": { kind: "rp-logout", backchannel: "accept" },
	"rp-frontchannel-opinitlogout": { kind: "op-frontchannel-logout" },
	"session-management": { kind: "session-management" },
};

function moduleSpec(module: string): ModuleSpec {
	const name = module.replace(/^oidcc-client-test-/, "");
	if (Object.hasOwn(MODULES, name)) {
		return MODULES[name];
	}
	// alg-none, no-event, with-nonce, wrong-alg, wrong-aud, wrong-event, wrong-iss
	if (name.startsWith("rp-backchannel-rpinitlogout-")) {
		return { kind: "rp-logout", backchannel: "reject" };
	}
	return { kind: "login" };
}

// ---------------------------------------------------------------------------------------------------------------
// state

interface StartInput {
	issuer: string;
	module: string;
	variant: Record<string, string>;
	clientMetadataDefaults: Record<string, unknown>;
	alias?: string;
	clientId?: string;
	clientSecret?: string;
	jwks?: { keys: jose.JWK[] };
}

interface RpClient {
	config: client.Configuration;
	clientId: string;
	/** what was sent at registration (dynamic) / configured (static) */
	requestedMetadata: Record<string, unknown>;
	clientAuth: client.ClientAuth;
	staticJwks?: { keys: jose.JWK[] };
}

interface LoginResult {
	claims?: Record<string, unknown>;
	idToken?: string;
	accessToken?: string;
	refreshToken?: string;
	userinfo?: Record<string, unknown>;
	sessionState?: string;
}

interface Flow {
	id: string;
	module: string;
	spec: ModuleSpec;
	input: StartInput;
	rp: RpClient;
	responseType: string;
	responseMode?: string;
	requestType: string;
	state: string;
	nonce: string;
	codeVerifier?: string;
	steps: string[];
	login: PromiseWithResolvers<LoginResult>;
	result?: LoginResult;
	loggedOut: PromiseWithResolvers<URLSearchParams>;
	frontchannel: PromiseWithResolvers<URLSearchParams>;
	backchannel: PromiseWithResolvers<{ accepted: boolean; error?: string }>;
	sessionCheck: Map<string, PromiseWithResolvers<string>>;
	endSessionState?: string;
	sid?: string;
	idTokenAlg?: string;
	waitingForInitiateLogin?: boolean;
	loggedIn: boolean;
}

const flows = new Map<string, Flow>();
const flowsByState = new Map<string, Flow>();
const requestObjects = new Map<string, string>();
let latestFlow: Flow | undefined;

function step(flow: { steps: string[]; module: string }, message: string): void {
	flow.steps.push(message);
	console.log(`[rp] ${flow.module}: ${message}`);
}

// ---------------------------------------------------------------------------------------------------------------
// user agent: the RP's "browser" (Playwright chromium) follows the front-channel redirects

interface UserAgent {
	open(url: string): Promise<void>;
	close(): Promise<void>;
}

// oxlint-disable-next-line typescript/no-explicit-any
let browserPromise: Promise<any> | undefined;

async function browserUserAgent(): Promise<UserAgent> {
	if (!browserPromise) {
		const executablePath = process.env["RP_CHROMIUM_EXECUTABLE_PATH"] ?? process.env["CHROMIUM_EXECUTABLE_PATH"];
		browserPromise = import("@playwright/test").then(({ chromium }) =>
			chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) }),
		);
		browserPromise.catch(() => {
			browserPromise = undefined;
		});
	}
	const browser = await browserPromise;
	const context = await browser.newContext({ ignoreHTTPSErrors: true });
	const pg = await context.newPage();
	if (DEBUG) {
		pg.on("framenavigated", (frame: { url(): string; parentFrame(): unknown }) => {
			if (!frame.parentFrame()) {
				console.log(`[rp] browser -> ${frame.url()}`);
			}
		});
		pg.on("console", (msg: { text(): string }) => console.log(`[rp] browser console: ${msg.text()}`));
	}
	return {
		async open(url) {
			await pg.goto(url, { waitUntil: "commit", timeout: LOGIN_TIMEOUT_MS }).catch((err: Error) => {
				if (DEBUG) {
					console.log(`[rp] browser navigation to ${url}: ${err.message}`);
				}
			});
		},
		close: () => context.close().catch(() => {}),
	};
}

// ---------------------------------------------------------------------------------------------------------------
// openid-client setup

function executeFor(issuer: string): ((config: client.Configuration) => void)[] {
	return new URL(issuer).protocol === "http:" ? [client.allowInsecureRequests] : [];
}

function grantTypesFor(responseType: string, refresh: boolean): string[] {
	const types = responseType.split(" ");
	return [
		...(types.includes("code") ? ["authorization_code"] : []),
		...(types.includes("id_token") || types.includes("token") ? ["implicit"] : []),
		...(refresh ? ["refresh_token"] : []),
	];
}

/** same rule as sample-openid-client-nodejs/helpers/needs_jwks.js */
function needsJwks(metadata: Record<string, unknown>): boolean {
	return (
		metadata["token_endpoint_auth_method"] === "private_key_jwt" ||
		(typeof metadata["request_object_signing_alg"] === "string" && metadata["request_object_signing_alg"] !== "none") ||
		!!metadata["authorization_encrypted_response_alg"] ||
		!!metadata["id_token_encrypted_response_alg"] ||
		!!metadata["userinfo_encrypted_response_alg"]
	);
}

async function clientAuthFor(
	method: string,
	metadata: Record<string, unknown>,
	input: StartInput,
): Promise<client.ClientAuth> {
	const secret =
		input.variant["client_registration"] === "static_client" ? (input.clientSecret ?? STATIC_CLIENT_SECRET) : undefined;
	switch (method) {
		case "none":
			return client.None();
		case "client_secret_basic":
			return client.ClientSecretBasic(secret);
		case "client_secret_post":
			return client.ClientSecretPost(secret);
		case "client_secret_jwt":
			return client.ClientSecretJwt(secret);
		case "private_key_jwt":
			return client.PrivateKeyJwt(
				await signingKey(String(metadata["token_endpoint_auth_signing_alg"] ?? "RS256"), input.jwks),
			);
		default:
			throw new Error(`client authentication method ${method} is not supported by this RP`);
	}
}

async function setUpClient(
	flowLike: { steps: string[]; module: string },
	input: StartInput,
	spec: ModuleSpec,
): Promise<RpClient> {
	const { variant } = input;
	const responseType = variant["response_type"] ?? "code";
	const requestType = spec.requestType ?? variant["request_type"] ?? "plain_http_request";
	const authMethod = variant["client_auth_type"] ?? "client_secret_basic";
	const execute = executeFor(input.issuer);

	const metadata: Record<string, unknown> = {
		...(requestType !== "plain_http_request" ? { request_object_signing_alg: "RS256" } : {}),
		// a web client with tokens in the front channel (any response type but code) must register https redirect_uris
		// that are not localhost (OIDC Registration 2, OIDCCValidateClientRedirectUris); this RP runs on localhost, so it
		// registers as a native (loopback) client, which may use http://localhost
		...(responseType !== "code" ? { application_type: "native" } : {}),
		...input.clientMetadataDefaults,
		token_endpoint_auth_method: authMethod,
		response_types: [responseType],
		grant_types: grantTypesFor(responseType, spec.kind === "refresh"),
		redirect_uris: [REDIRECT_URI],
		...spec.metadata,
	};
	if (spec.kind === "rp-logout" || spec.kind === "op-frontchannel-logout" || spec.kind === "session-management") {
		Object.assign(metadata, {
			post_logout_redirect_uris: [POST_LOGOUT_REDIRECT_URI],
			backchannel_logout_uri: BACKCHANNEL_LOGOUT_URI,
			backchannel_logout_session_required: true,
			frontchannel_logout_uri: FRONTCHANNEL_LOGOUT_URI,
			frontchannel_logout_session_required: true,
		});
	}
	if (spec.kind === "3rd-party") {
		metadata["initiate_login_uri"] = INITIATE_LOGIN_URI;
	}

	let rp: RpClient;
	if (variant["client_registration"] === "static_client") {
		const clientId = input.clientId ?? STATIC_CLIENT_ID;
		const clientMetadata = { ...metadata, client_secret: input.clientSecret ?? STATIC_CLIENT_SECRET };
		const clientAuth = await clientAuthFor(authMethod, clientMetadata, input);
		const config = await client.discovery(new URL(input.issuer), clientId, clientMetadata, clientAuth, { execute });
		step(flowLike, `discovered ${config.serverMetadata().issuer}, using static client ${clientId}`);
		rp = { config, clientId, requestedMetadata: clientMetadata, clientAuth, staticJwks: input.jwks };
	} else {
		if (needsJwks(metadata) && !("jwks" in metadata) && !("jwks_uri" in metadata)) {
			metadata["jwks"] = PUBLIC_JWKS;
		}
		const clientAuth = await clientAuthFor(authMethod, metadata, input);
		const config = await client.dynamicClientRegistration(
			new URL(input.issuer),
			metadata as Partial<client.ClientMetadata>,
			clientAuth,
			{ execute },
		);
		const clientId = config.clientMetadata().client_id;
		step(flowLike, `discovered ${config.serverMetadata().issuer} and registered client ${clientId} (${authMethod})`);
		rp = { config, clientId, requestedMetadata: metadata, clientAuth };
	}
	await configureResponseHandling(rp.config, responseType);
	return rp;
}

async function configureResponseHandling(config: client.Configuration, responseType: string): Promise<void> {
	const types = new Set(responseType.split(" "));
	if (types.has("id_token") && types.has("code")) {
		client.useCodeIdTokenResponseType(config);
	} else if (types.has("id_token")) {
		client.useIdTokenResponseType(config);
	}
	// validate ID Token signatures from the token endpoint too (oidcc-client-test-invalid-sig-*, kid-absent-*)
	client.enableNonRepudiationChecks(config);
	const md = config.clientMetadata();
	const algs = [md.id_token_encrypted_response_alg, md.userinfo_encrypted_response_alg].filter(
		(a): a is string => typeof a === "string",
	);
	const keys = algs.length ? await decryptionKeys(algs) : [];
	if (keys.length) {
		client.enableDecryptingResponses(config, undefined, ...keys);
	}
}

/** a fresh Configuration for the same client, i.e. without cached JWKS (key rotation modules) */
async function freshConfig(rp: RpClient, responseType: string, issuer: string): Promise<client.Configuration> {
	const config = new client.Configuration(
		rp.config.serverMetadata(),
		rp.clientId,
		{ ...rp.config.clientMetadata() },
		rp.clientAuth,
	);
	for (const ext of executeFor(issuer)) {
		ext(config);
	}
	await configureResponseHandling(config, responseType);
	return config;
}

// ---------------------------------------------------------------------------------------------------------------
// authorization request

function newFlow(input: StartInput, spec: ModuleSpec, rp: RpClient, steps: string[]): Flow {
	const variant = input.variant;
	const responseMode =
		variant["response_mode"] && variant["response_mode"] !== "default" ? variant["response_mode"] : undefined;
	const flow: Flow = {
		id: randomUUID(),
		module: input.module,
		spec,
		input,
		rp,
		responseType: variant["response_type"] ?? "code",
		responseMode,
		requestType: spec.requestType ?? variant["request_type"] ?? "plain_http_request",
		state: client.randomState(),
		nonce: client.randomNonce(),
		steps,
		login: deferred(),
		loggedOut: deferred(),
		frontchannel: deferred(),
		backchannel: deferred(),
		sessionCheck: new Map([
			["before", deferred<string>()],
			["after", deferred<string>()],
		]),
		loggedIn: false,
	};
	flows.set(flow.id, flow);
	flowsByState.set(flow.state, flow);
	latestFlow = flow;
	return flow;
}

async function buildAuthorizationUrl(flow: Flow, extra: Record<string, string> = {}): Promise<URL> {
	const { config } = flow.rp;
	const params: Record<string, string> = {
		redirect_uri: REDIRECT_URI,
		scope: "openid",
		response_type: flow.responseType,
		state: flow.state,
		// always send a nonce (required for id_token response types, recommended for code)
		nonce: flow.nonce,
		...(flow.responseMode ? { response_mode: flow.responseMode } : {}),
		...flow.spec.params,
		...extra,
	};
	if (flow.responseType.split(" ").includes("code")) {
		flow.codeVerifier = client.randomPKCECodeVerifier();
		params["code_challenge"] = await client.calculatePKCECodeChallenge(flow.codeVerifier);
		params["code_challenge_method"] = "S256";
	}

	if (flow.requestType === "plain_http_request") {
		return client.buildAuthorizationUrl(config, params);
	}

	const alg = String(
		config.clientMetadata().request_object_signing_alg ??
			flow.rp.requestedMetadata["request_object_signing_alg"] ??
			"RS256",
	);
	let requestObject: string;
	if (alg === "none") {
		requestObject = new jose.UnsecuredJWT({ ...params, client_id: flow.rp.clientId })
			.setIssuer(flow.rp.clientId)
			.setAudience(config.serverMetadata().issuer)
			.setIssuedAt()
			.setNotBefore("0s")
			.setExpirationTime("5m")
			.setJti(randomUUID())
			.encode();
	} else {
		const jarUrl = await client.buildAuthorizationUrlWithJAR(config, params, await signingKey(alg, flow.rp.staticJwks));
		requestObject = jarUrl.searchParams.get("request")!;
	}

	// OIDC Core 6.1: response_type, client_id (and scope with openid) are also sent as plain parameters
	const url = new URL(config.serverMetadata().authorization_endpoint!);
	url.searchParams.set("client_id", flow.rp.clientId);
	url.searchParams.set("response_type", flow.responseType);
	url.searchParams.set("scope", params["scope"]);
	if (flow.requestType === "request_uri") {
		const id = randomUUID();
		requestObjects.set(id, requestObject);
		const requestUri = `${REQUEST_OBJECT_BASE}${id}`;
		url.searchParams.set("request_uri", requestUri);
		step(flow, `request object (alg ${alg}) hosted at ${requestUri}`);
	} else {
		url.searchParams.set("request", requestObject);
		step(flow, `request object (alg ${alg}) passed by value`);
	}
	return url;
}

// ---------------------------------------------------------------------------------------------------------------
// authorization response handling

const FRONT_CHANNEL_TOKEN_PARAMS = ["access_token", "token_type", "expires_in", "session_state"];

async function completeLogin(flow: Flow, params: URLSearchParams, config = flow.rp.config): Promise<LoginResult> {
	step(flow, `authorization response received (${[...params.keys()].join(", ") || "no parameters"})`);
	const types = new Set(flow.responseType.split(" "));
	const result: LoginResult = { sessionState: params.get("session_state") ?? undefined };
	const frontIdToken = params.get("id_token") ?? undefined;
	const frontAccessToken = params.get("access_token") ?? undefined;

	const libParams = new URLSearchParams(params);
	for (const p of FRONT_CHANNEL_TOKEN_PARAMS) {
		libParams.delete(p);
	}
	const currentUrl = new URL(REDIRECT_URI);

	// error responses are left to openid-client too: it validates state / iss and raises AuthorizationResponseError
	if (types.has("code")) {
		if (frontIdToken && frontAccessToken) {
			// code id_token token: the front-channel access token is validated before the code is exchanged, an
			// id_token with a missing / invalid at_hash must not lead to a token request
			// (oidcc-client-test-missing-athash, oidcc-client-test-invalid-athash)
			await validateAtHash(frontIdToken, frontAccessToken);
			step(flow, "at_hash validated");
		}
		if (types.has("id_token")) {
			currentUrl.hash = libParams.toString();
		} else {
			currentUrl.search = libParams.toString();
		}
		const tokens = await client.authorizationCodeGrant(config, currentUrl, {
			pkceCodeVerifier: flow.codeVerifier,
			expectedState: flow.state,
			expectedNonce: flow.nonce,
			idTokenExpected: true,
		});
		step(flow, `token endpoint response validated (token_type ${tokens.token_type})`);
		result.claims = tokens.claims() as Record<string, unknown> | undefined;
		result.idToken = tokens.id_token;
		result.accessToken = tokens.access_token;
		result.refreshToken = tokens.refresh_token;
	} else {
		currentUrl.hash = libParams.toString();
		result.claims = (await client.implicitAuthentication(config, currentUrl, flow.nonce, {
			expectedState: flow.state,
		})) as unknown as Record<string, unknown>;
		step(flow, "front-channel ID Token validated");
		result.idToken = frontIdToken;
		result.accessToken = frontAccessToken;
		if (frontIdToken && frontAccessToken) {
			// id_token token
			await validateAtHash(frontIdToken, frontAccessToken);
			step(flow, "at_hash validated");
		}
	}

	if (result.idToken) {
		flow.idTokenAlg = String(jose.decodeProtectedHeader(result.idToken).alg ?? "");
	}
	flow.sid = typeof result.claims?.["sid"] === "string" ? (result.claims["sid"] as string) : undefined;

	if (result.accessToken && !flow.spec.skipUserinfo) {
		result.userinfo = await userinfo(flow, config, result.accessToken, String(result.claims?.["sub"]));
	}

	flow.spec.check?.(result);
	return result;
}

async function userinfo(
	flow: Flow,
	config: client.Configuration,
	accessToken: string,
	sub: string,
): Promise<Record<string, unknown>> {
	let info: Record<string, unknown>;
	if (flow.spec.userinfoVia === "body") {
		// RFC 6750 section 2.2 form-encoded body parameter (openid-client only sends the Authorization header)
		const res = await fetch(config.serverMetadata().userinfo_endpoint!, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json, application/jwt" },
			body: new URLSearchParams({ access_token: accessToken }),
		});
		if (!res.ok) {
			throw new Error(`userinfo endpoint responded with ${res.status}`);
		}
		const body = await res.text();
		info = (res.headers.get("content-type") ?? "").includes("jwt") ? jose.decodeJwt(body) : JSON.parse(body);
		if (info["sub"] !== sub) {
			throw new Error(`userinfo sub mismatch, expected ${sub}, got: ${String(info["sub"])}`);
		}
	} else {
		info = (await client.fetchUserInfo(config, accessToken, sub)) as Record<string, unknown>;
	}
	step(flow, "userinfo response validated");
	await resolveClaimSources(flow, info, accessToken);
	return info;
}

/** OIDC Core 5.6.2 aggregated and distributed claims */
async function resolveClaimSources(flow: Flow, claims: Record<string, unknown>, accessToken: string): Promise<void> {
	const names = claims["_claim_names"] as Record<string, string> | undefined;
	const sources = claims["_claim_sources"] as
		| Record<string, { JWT?: string; endpoint?: string; access_token?: string }>
		| undefined;
	if (!names || !sources) {
		return;
	}
	const resolved = new Map<string, Record<string, unknown>>();
	for (const [claim, sourceName] of Object.entries(names)) {
		const source = sources[sourceName];
		if (!source) {
			continue;
		}
		let payload = resolved.get(sourceName);
		if (!payload) {
			if (source.JWT) {
				payload = jose.decodeJwt(source.JWT);
				step(flow, `aggregated claims source ${sourceName} unpacked`);
			} else if (source.endpoint) {
				const res = await fetch(source.endpoint, {
					headers: { authorization: `Bearer ${source.access_token ?? accessToken}`, accept: "application/jwt" },
				});
				if (!res.ok) {
					throw new Error(`distributed claims endpoint responded with ${res.status}`);
				}
				const body = (await res.text()).trim();
				payload = body.startsWith("{") ? JSON.parse(body) : jose.decodeJwt(body);
				step(flow, `distributed claims fetched from ${source.endpoint}`);
			} else {
				continue;
			}
			resolved.set(sourceName, payload!);
		}
		if (payload![claim] !== undefined) {
			claims[claim] = payload![claim];
		}
	}
	delete claims["_claim_names"];
	delete claims["_claim_sources"];
}

async function handleAuthorizationResponse(res: ServerResponse, params: URLSearchParams): Promise<void> {
	const state = params.get("state");
	const flow = (state ? flowsByState.get(state) : undefined) ?? latestFlow;
	if (!flow) {
		return send(res, 400, page("Error", "<h1>No login in progress</h1>"));
	}
	try {
		const result = await completeLogin(flow, params);
		flow.result = result;
		flow.loggedIn = true;
		flow.login.resolve(result);
		const sub = htmlSafe(result.claims?.["sub"] ?? "?");
		send(res, 200, page("Signed in", `<h1 id="rp-login-complete">Signed in as ${sub}</h1>`));
	} catch (err) {
		step(flow, `authorization response rejected: ${describeError(err)}`);
		flow.login.reject(err);
		const pre = `<pre>${htmlSafe(describeError(err))}</pre>`;
		send(res, 400, page("Login failed", `<h1 id="rp-login-failed">Login failed</h1>${pre}`));
	}
}

// ---------------------------------------------------------------------------------------------------------------
// module runners

interface StartResult {
	ok: boolean;
	error?: string;
	steps: string[];
	module: string;
	outcome?: string;
}

async function runModule(input: StartInput): Promise<StartResult> {
	const spec = moduleSpec(input.module);
	const { module } = input;
	const steps: string[] = [];
	const ctx = { steps, module };
	step(
		ctx,
		`start (variant ${JSON.stringify(input.variant)}, metadata defaults ${JSON.stringify(input.clientMetadataDefaults)})`,
	);

	/** runs fn; for negative modules the RP passes when fn throws (like the sample client's assert.rejects) */
	const expect = async (fn: () => Promise<unknown>, outcome?: string): Promise<StartResult> => {
		if (!spec.expectFailure) {
			await fn();
			return { ok: true, steps, module, outcome };
		}
		try {
			await fn();
		} catch (err) {
			step(ctx, `rejected as expected: ${describeError(err)}`);
			return { ok: true, steps, module, outcome: "rejected", error: describeError(err) };
		}
		return { ok: false, error: "the RP did not reject the response", steps, module, outcome: "accepted" };
	};

	const execute = executeFor(input.issuer);
	const discover = async (issuer: string) => {
		const config = await client.discovery(new URL(issuer), "discovery-only", undefined, client.None(), { execute });
		step(ctx, `discovered ${config.serverMetadata().issuer}`);
		return config;
	};
	switch (spec.kind) {
		case "discovery":
			return expect(() => discover(input.issuer));
		case "jwks":
			return expect(async () => {
				const config = await discover(input.issuer);
				const jwks = (await (await fetch(config.serverMetadata().jwks_uri!)).json()) as jose.JSONWebKeySet;
				jose.createLocalJWKSet(jwks);
				step(ctx, `fetched jwks_uri with ${jwks.keys.length} keys`);
			});
		case "webfinger-acct":
		case "webfinger-url":
		case "issuer-mismatch": {
			const issuerUrl = new URL(input.issuer);
			const alias = input.alias ?? issuerUrl.pathname.replace(/^\/test\/a\//, "").replace(/\/$/, "");
			const resource =
				spec.kind === "webfinger-acct" ? `acct:${alias}.${module}@${issuerUrl.host}` : `${input.issuer}${module}`;
			return expect(async () => {
				const href = await webfinger(resource, issuerUrl.protocol);
				step(ctx, `webfinger ${resource} -> ${href}`);
				await discover(href);
			});
		}
		case "register":
			return expect(() => setUpClient(ctx, input, spec));
		default:
			break;
	}

	const rp = await setUpClient(ctx, input, spec);
	const flow = newFlow(input, spec, rp, steps);

	if (spec.kind === "3rd-party") {
		flow.waitingForInitiateLogin = true;
		step(flow, `waiting for the OP to send the user to ${INITIATE_LOGIN_URI}`);
		try {
			const result = await withTimeout(flow.login.promise, LOGIN_TIMEOUT_MS * 2, "third party initiated login");
			return { ok: true, steps, module, outcome: `signed in as ${String(result.claims?.["sub"])}` };
		} finally {
			flow.waitingForInitiateLogin = false;
		}
	}

	const ua = await browserUserAgent();
	try {
		// the user agent starts at the RP's /login (like a login button), which redirects to the OP
		const login = async (target = flow) => {
			await ua.open(`${BASE}/login?flow=${target.id}`);
			return withTimeout(target.login.promise, LOGIN_TIMEOUT_MS, "the authorization response");
		};

		if (spec.kind === "login") {
			return await expect(() => login(), "signed in");
		}

		if (spec.kind === "refresh") {
			const result = await login();
			if (!result.refreshToken) {
				throw new Error("no refresh_token was issued");
			}
			return await expect(async () => {
				const tokens = await client.refreshTokenGrant(rp.config, result.refreshToken!);
				step(flow, "refresh token grant response validated");
				const claims = tokens.claims();
				if (claims && result.claims && claims.sub !== result.claims["sub"]) {
					throw new Error(`sub mismatch, expected ${String(result.claims["sub"])}, got: ${claims.sub}`);
				}
				if (claims && result.claims && claims.iss !== result.claims["iss"]) {
					throw new Error(`unexpected iss value, expected ${String(result.claims["iss"])}, got: ${claims.iss}`);
				}
				await userinfo(flow, rp.config, tokens.access_token, String(result.claims?.["sub"]));
			}, "refreshed");
		}

		if (spec.kind === "key-rotation") {
			await login();
			// second authentication with a configuration that has no cached JWKS, so the rotated key is fetched
			const config = await freshConfig(rp, flow.responseType, input.issuer);
			const second = newFlow(input, spec, { ...rp, config }, steps);
			step(flow, "second authentication after OP key rotation");
			await login(second);
			return { ok: true, steps, module, outcome: "signed in twice" };
		}

		// logout / session modules
		await login();

		if (spec.kind === "session-management") {
			await sessionCheck(flow, ua, "before", "unchanged");
		}

		if (spec.kind === "op-frontchannel-logout") {
			step(flow, "waiting for the OP initiated front-channel logout request");
			await withTimeout(flow.frontchannel.promise, LOGIN_TIMEOUT_MS, "the front-channel logout request");
			step(flow, "front-channel logout received, session cleared");
			return { ok: true, steps, module, outcome: "logged out (front-channel)" };
		}

		step(flow, "RP-initiated logout");
		await ua.open(`${BASE}/logout?flow=${flow.id}`);
		const redirectParams = await withTimeout(flow.loggedOut.promise, LOGIN_TIMEOUT_MS, "the post logout redirect");
		const returnedState = redirectParams.get("state");
		step(
			flow,
			`post logout redirect received (state ${returnedState === null ? "absent" : returnedState === flow.endSessionState ? "matches" : "does not match"})`,
		);

		if (spec.backchannel) {
			const outcome = await withTimeout(flow.backchannel.promise, 5000, "the back-channel logout request");
			const accepted = outcome.accepted ? "accepted" : `rejected (${outcome.error})`;
			step(flow, `back-channel logout_token ${accepted}`);
			if ((spec.backchannel === "accept") !== outcome.accepted) {
				const error = `expected the logout_token to be ${spec.backchannel}ed but it was ${accepted}`;
				return { ok: false, error, steps, module };
			}
		}

		if (spec.kind === "session-management") {
			await sessionCheck(flow, ua, "after", "changed");
		}
		return { ok: true, steps, module, outcome: "logged out" };
	} finally {
		await ua.close();
	}
}

async function sessionCheck(flow: Flow, ua: UserAgent, phase: "before" | "after", expected: string): Promise<void> {
	await ua.open(`${BASE}/session-check?flow=${flow.id}&phase=${phase}`);
	const answer = flow.sessionCheck.get(phase)!.promise;
	const result = await withTimeout(answer, 15_000, `the check_session_iframe answer (${phase} logout)`);
	step(flow, `check_session_iframe ${phase} logout: ${result}`);
	if (result !== expected) {
		throw new Error(`check_session_iframe answered "${result}" ${phase} logout, expected "${expected}"`);
	}
}

async function webfinger(resource: string, protocol: string): Promise<string> {
	const origin = resource.startsWith("acct:")
		? `${protocol}//${resource.slice(resource.lastIndexOf("@") + 1)}`
		: new URL(resource).origin;
	const url = new URL("/.well-known/webfinger", origin);
	url.searchParams.set("resource", resource);
	url.searchParams.set("rel", "http://openid.net/specs/connect/1.0/issuer");
	const res = await fetch(url, { headers: { accept: "application/jrd+json, application/json" } });
	if (!res.ok) {
		throw new Error(`webfinger responded with ${res.status}`);
	}
	const body = (await res.json()) as { links?: { rel?: string; href?: string }[] };
	const link = body.links?.find((l) => l.rel === "http://openid.net/specs/connect/1.0/issuer");
	if (!link?.href) {
		throw new Error("webfinger response has no OpenID Connect issuer link");
	}
	return link.href;
}

// ---------------------------------------------------------------------------------------------------------------
// logout endpoints

async function validateLogoutToken(flow: Flow, logoutToken: string): Promise<void> {
	const server = flow.rp.config.serverMetadata();
	const alg = flow.idTokenAlg || String(flow.rp.config.clientMetadata().id_token_signed_response_alg ?? "RS256");
	const jwks = jose.createRemoteJWKSet(new URL(server.jwks_uri!));
	// OIDC Back-Channel Logout 1.0 section 2.6: validate like an ID Token, plus the logout specific claims
	const { payload } = await jose.jwtVerify(logoutToken, jwks, {
		issuer: server.issuer,
		audience: flow.rp.clientId,
		algorithms: [alg],
		requiredClaims: ["iat", "jti", "events"],
		clockTolerance: 30,
	});
	const events = payload["events"] as Record<string, unknown> | undefined;
	if (!events || typeof events !== "object" || typeof events[BACKCHANNEL_LOGOUT_EVENT] !== "object") {
		throw new Error(`logout_token events claim does not contain ${BACKCHANNEL_LOGOUT_EVENT}`);
	}
	if ("nonce" in payload) {
		throw new Error("logout_token must not contain a nonce claim");
	}
	if (!payload.sub && !payload["sid"]) {
		throw new Error("logout_token contains neither sub nor sid");
	}
	if (payload["sid"] && flow.sid && payload["sid"] !== flow.sid) {
		throw new Error("logout_token sid does not match the session");
	}
}

function findFlowForLogout(predicate: (f: Flow) => boolean): Flow | undefined {
	const candidates = [...flows.values()].filter((f) => f.loggedIn && predicate(f));
	return candidates.at(-1) ?? (latestFlow?.loggedIn ? latestFlow : undefined);
}

// ---------------------------------------------------------------------------------------------------------------
// HTTP server

async function readBody(req: IncomingMessage): Promise<string> {
	const chunks: Buffer[] = [];
	for await (const chunk of req) {
		chunks.push(chunk as Buffer);
	}
	return Buffer.concat(chunks).toString("utf8");
}

function send(res: ServerResponse, status: number, body: string, headers: Record<string, string> = {}): void {
	res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers });
	res.end(body);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
	send(res, status, JSON.stringify(body), { "content-type": "application/json" });
}

function redirect(res: ServerResponse, location: string): void {
	res.writeHead(302, { location, "cache-control": "no-store" });
	res.end();
}

async function redirectToAuthorization(res: ServerResponse, flow: Flow, extra?: Record<string, string>): Promise<void> {
	const { href } = await buildAuthorizationUrl(flow, extra);
	step(flow, `authorization request ${href.length > 300 ? `${href.slice(0, 300)}...` : href}`);
	redirect(res, href);
}

/** /cb for fragment encoded responses: hand the fragment to the server like any SPA callback page would */
const FRAGMENT_PAGE = page(
	"Processing login",
	`<p>Processing the authorization response...</p>
<script>
var form = document.createElement("form");
form.method = "POST";
form.action = "/cb-fragment";
new URLSearchParams(window.location.hash.slice(1)).forEach(function (value, key) {
	var input = document.createElement("input");
	input.type = "hidden";
	input.name = key;
	input.value = value;
	form.appendChild(input);
});
document.body.appendChild(form);
form.submit();
</script>`,
);

function sessionCheckPage(flow: Flow, phase: string): string {
	const server = flow.rp.config.serverMetadata();
	const iframe = server["check_session_iframe"] as string | undefined;
	if (!iframe || !flow.result?.sessionState) {
		return page("Session check", "<p>The OP does not support session management</p>");
	}
	const status = `${BASE}/session-status?flow=${encodeURIComponent(flow.id)}&phase=${encodeURIComponent(phase)}`;
	return page(
		"Session check",
		`<p id="result">checking session (${htmlSafe(phase)} logout)...</p>
<iframe id="op_iframe" src="${htmlSafe(iframe)}" onload="opLoaded()" hidden></iframe>`,
		`<script>
var MESSAGE = ${jsString(`${flow.rp.clientId} ${flow.result.sessionState}`)};
var OP_ORIGIN = ${jsString(new URL(iframe).origin)};
var STATUS_URL = ${jsString(status)};
var answered = false;
window.addEventListener("message", function (e) {
	if (e.origin !== OP_ORIGIN || typeof e.data !== "string" || answered) return;
	answered = true;
	fetch(STATUS_URL + "&result=" + encodeURIComponent(e.data)).then(function () {
		document.getElementById("result").textContent = "session " + e.data;
	});
}, false);
function opLoaded() {
	setTimeout(function () {
		document.getElementById("op_iframe").contentWindow.postMessage(MESSAGE, OP_ORIGIN);
	}, 300);
}
</script>`,
	);
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
	const url = new URL(req.url ?? "/", BASE);
	if (DEBUG) {
		console.log(`[rp] ${req.method} ${url.pathname}${url.search}`);
	}
	const q = url.searchParams;
	const flow = flows.get(q.get("flow") ?? "");
	const error = (status: number, message: string) => send(res, status, page("Error", `<h1>${message}</h1>`));

	switch (`${req.method} ${url.pathname}`) {
		case "GET /":
		case "GET /ready":
			return sendJson(res, 200, {
				ready: true,
				base: BASE,
				redirect_uri: REDIRECT_URI,
				initiate_login_uri: INITIATE_LOGIN_URI,
			});

		case "GET /jwks":
			return sendJson(res, 200, PUBLIC_JWKS);

		case "GET /start":
			return startModule(res, q);

		case "GET /login":
			return flow ? redirectToAuthorization(res, flow) : error(404, "unknown login");

		case "GET /cb":
			return url.search ? handleAuthorizationResponse(res, q) : send(res, 200, FRAGMENT_PAGE);

		case "POST /cb":
		case "POST /cb-fragment":
			return handleAuthorizationResponse(res, new URLSearchParams(await readBody(req)));

		case "GET /logout": {
			if (!flow?.result?.idToken) {
				return error(400, "not signed in");
			}
			flow.endSessionState = client.randomState();
			const endSession = client.buildEndSessionUrl(flow.rp.config, {
				id_token_hint: flow.result.idToken,
				post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
				state: flow.endSessionState,
			});
			step(flow, `redirecting to end_session_endpoint ${endSession.origin}${endSession.pathname}`);
			return redirect(res, endSession.href);
		}

		case "GET /logged-out": {
			const state = q.get("state");
			const loggingOut = [...flows.values()].filter((f) => f.endSessionState);
			const target = loggingOut.find((f) => f.endSessionState === state) ?? loggingOut.at(-1);
			if (target) {
				target.loggedIn = false;
				target.loggedOut.resolve(q);
			}
			return send(res, 200, page("Signed out", '<h1 id="rp-logged-out">Signed out</h1>'));
		}

		case "POST /backchannel-logout":
			return backchannelLogout(res, new URLSearchParams(await readBody(req)).get("logout_token"));

		case "GET /frontchannel-logout": {
			const iss = q.get("iss");
			const sid = q.get("sid");
			const target = findFlowForLogout(
				(f) => (!sid || f.sid === sid) && (!iss || f.rp.config.serverMetadata().issuer === iss),
			);
			if (target) {
				target.loggedIn = false;
				step(target, `front-channel logout received (iss ${iss ?? "-"}, sid ${sid ?? "-"}), session cleared`);
				target.frontchannel.resolve(q);
			}
			return send(res, 200, page("Signed out", "<p>Signed out</p>"));
		}

		case "GET /session-check":
			return flow ? send(res, 200, sessionCheckPage(flow, q.get("phase") ?? "before")) : error(404, "unknown session");

		case "GET /session-status":
			flow?.sessionCheck.get(q.get("phase") ?? "")?.resolve(q.get("result") ?? "");
			return sendJson(res, 200, { ok: !!flow });

		case "GET /initiate-login": {
			// OIDC Core 4: third party initiated login (iss, login_hint, target_link_uri)
			const iss = q.get("iss") ?? "";
			const target = [...flows.values()]
				.filter((f) => f.waitingForInitiateLogin && norm(f.rp.config.serverMetadata().issuer) === norm(iss))
				.at(-1);
			if (!target) {
				return error(400, `unknown issuer ${htmlSafe(iss)}`);
			}
			step(target, `initiate_login_uri called (iss ${iss})`);
			const loginHint = q.get("login_hint");
			return redirectToAuthorization(res, target, loginHint ? { login_hint: loginHint } : {});
		}

		default:
			break;
	}

	if (req.method === "GET" && url.pathname.startsWith("/request-object/")) {
		const jwt = requestObjects.get(url.pathname.slice("/request-object/".length));
		return jwt
			? send(res, 200, jwt, { "content-type": "application/oauth-authz-req+jwt" })
			: send(res, 404, "not found", { "content-type": "text/plain" });
	}

	return send(res, 404, page("Not found", "<h1>not found</h1>"));
}

/** GET /start: the driver entry point (README.md "Driver contract") */
async function startModule(res: ServerResponse, q: URLSearchParams): Promise<void> {
	const issuer = q.get("issuer");
	const module = q.get("module");
	if (!issuer || !module) {
		return sendJson(res, 400, { ok: false, error: "issuer and module query parameters are required", steps: [] });
	}
	const json = (name: string) => {
		const value = q.get(name);
		return value ? JSON.parse(value) : undefined;
	};
	let input: StartInput;
	try {
		input = {
			issuer,
			module,
			variant: json("variant") ?? {},
			clientMetadataDefaults: json("client_metadata_defaults") ?? {},
			alias: q.get("alias") ?? undefined,
			clientId: q.get("client_id") ?? undefined,
			clientSecret: q.get("client_secret") ?? undefined,
			jwks: json("jwks"),
		};
	} catch (err) {
		return sendJson(res, 400, { ok: false, error: describeError(err), steps: [] });
	}
	let result: StartResult;
	try {
		result = await runModule(input);
	} catch (err) {
		console.log(`[rp] ${module}: failed: ${describeError(err)}`);
		result = { ok: false, error: describeError(err), steps: [], module };
	}
	if (!result.steps.length) {
		result.steps = [...(latestFlow?.module === module ? latestFlow.steps : [])];
	}
	console.log(`[rp] ${module}: ${result.ok ? "OK" : "NOT OK"}${result.error ? ` - ${result.error}` : ""}`);
	sendJson(res, 200, result);
}

/** POST /backchannel-logout: 200 when the logout_token is valid for a signed in flow, 400 otherwise */
async function backchannelLogout(res: ServerResponse, logoutToken: string | null): Promise<void> {
	let flow: Flow | undefined;
	try {
		if (!logoutToken) {
			throw new Error("logout_token missing");
		}
		let claims: jose.JWTPayload = {};
		try {
			claims = jose.decodeJwt(logoutToken);
		} catch {
			// validated below
		}
		const sid = claims["sid"];
		flow = findFlowForLogout((f) => (sid !== undefined && f.sid === sid) || f.rp.clientId === claims.aud);
		if (!flow) {
			throw new Error("no session for this logout_token");
		}
		await validateLogoutToken(flow, logoutToken);
		flow.loggedIn = false;
		step(flow, "back-channel logout_token accepted, session cleared");
		flow.backchannel.resolve({ accepted: true });
		send(res, 200, "", { "content-type": "text/plain" });
	} catch (err) {
		const error = describeError(err);
		if (flow) {
			step(flow, `back-channel logout_token rejected: ${error}`);
		}
		(flow ?? latestFlow)?.backchannel.resolve({ accepted: false, error });
		sendJson(res, 400, { error: "invalid_request", error_description: error });
	}
}

function handler(req: IncomingMessage, res: ServerResponse): void {
	handle(req, res).catch((err) => {
		console.error("[rp] request failed", err);
		if (!res.headersSent) {
			sendJson(res, 500, { error: describeError(err) });
		} else {
			res.end();
		}
	});
}

function listen(server: Server, port: number): Promise<Server> {
	return new Promise((resolve, reject) => {
		server.once("error", reject).listen(port, "localhost", () => resolve(server));
	});
}

export interface RunningRp {
	base: string;
	close(): Promise<void>;
}

export async function start(): Promise<RunningRp> {
	await initKeys();
	const servers = [await listen(createServer(handler), PORT)];
	if (HTTPS_PORT) {
		const tls = {
			cert: readFileSync(new URL("localhost.crt", CERTS)),
			key: readFileSync(new URL("localhost.key", CERTS)),
		};
		servers.push(await listen(createHttpsServer(tls, handler), HTTPS_PORT));
	}
	return {
		base: BASE,
		async close() {
			for (const s of servers) {
				s.closeAllConnections();
				await new Promise<void>((resolve) => s.close(() => resolve()));
			}
			if (browserPromise) {
				await browserPromise.then((b) => b.close()).catch(() => {});
			}
		},
	};
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
	const running = await start();
	console.log(
		`openid-client RP listening on ${BASE} (redirect_uri ${REDIRECT_URI}, initiate_login_uri ${INITIATE_LOGIN_URI})`,
	);
	console.log("ready");
	const shutdown = () => void running.close().then(() => process.exit(0));
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
