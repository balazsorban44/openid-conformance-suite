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
 *   RP_HTTPS_PORT (4443)              https listener (self-signed, needs openssl) for initiate_login_uri, 0 disables
 *   RP_STATIC_CLIENT_ID / RP_STATIC_CLIENT_SECRET   static client defaults (openid-client-rp / rp-secret-...)
 *   RP_JWKS                           private JWKS JSON to use instead of keys generated at startup
 *   RP_USER_AGENT (browser|fetch)     how front-channel navigation is performed (default browser: Playwright chromium)
 *   RP_CHROMIUM_EXECUTABLE_PATH       chromium binary for the browser user agent (default: Playwright's)
 *   RP_LOGIN_TIMEOUT_MS (30000)       how long to wait for an authorization round trip
 *   DEBUG_RP=1                        verbose logging
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

const REDIRECT_URI = `${BASE}/cb`;
const POST_LOGOUT_REDIRECT_URI = `${BASE}/logged-out`;
const BACKCHANNEL_LOGOUT_URI = `${BASE}/backchannel-logout`;
const FRONTCHANNEL_LOGOUT_URI = `${BASE}/frontchannel-logout`;
const INITIATE_LOGIN_URI = `${HTTPS_BASE}/initiate-login`;
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
		const gen = async (alg: string, use: string, options: jose.GenerateKeyPairOptions = {}) => {
			const { privateKey } = await jose.generateKeyPair(alg, { ...options, extractable: true });
			const jwk = await jose.exportJWK(privateKey);
			jwk.use = use;
			jwk.kid = await jose.calculateJwkThumbprint(jwk);
			return jwk;
		};
		KEYS = {
			rsaSig: await gen("RS256", "sig", { modulusLength: 2048 }),
			ecSig: await gen("ES256", "sig"),
			edSig: await gen("Ed25519", "sig"),
			rsaEnc: await gen("RSA-OAEP", "enc", { modulusLength: 2048 }),
			ecEnc: await gen("ECDH-ES", "enc", { crv: "P-256" }),
		};
	}
	PUBLIC_JWKS = { keys: Object.values(KEYS).map(publicJwk) };
}

function publicJwk(jwk: jose.JWK): jose.JWK {
	const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = jwk;
	return pub;
}

/** private signing key for a JWS alg (private_key_jwt assertions, request objects) */
async function signingKey(alg: string, jwks?: { keys: jose.JWK[] }): Promise<client.PrivateKey> {
	let jwk: jose.JWK;
	if (jwks) {
		const candidates = jwks.keys.filter((k) => k.d && k.use !== "enc");
		const kty = alg.startsWith("ES") ? "EC" : alg.startsWith("RS") || alg.startsWith("PS") ? "RSA" : "OKP";
		const found = candidates.find((k) => k.kty === kty);
		if (!found) {
			throw new Error(`static client jwks has no private ${kty} key for ${alg}`);
		}
		jwk = found;
	} else if (alg.startsWith("RS") || alg.startsWith("PS")) {
		jwk = KEYS.rsaSig;
	} else if (alg === "ES256") {
		jwk = KEYS.ecSig;
	} else if (alg === "EdDSA" || alg === "Ed25519") {
		jwk = KEYS.edSig;
	} else {
		throw new Error(`no RP signing key for alg ${alg}`);
	}
	const { use: _use, alg: _alg, key_ops: _ops, ...material } = jwk;
	const key = (await jose.importJWK(material, alg)) as client.CryptoKey;
	return { key, kid: jwk.kid };
}

/** decryption keys for the registered id_token / userinfo encryption algs */
async function decryptionKeys(algs: string[]): Promise<client.DecryptionKey[]> {
	const keys: client.DecryptionKey[] = [];
	for (const alg of new Set(algs)) {
		let jwk: jose.JWK;
		if (alg.startsWith("RSA-OAEP")) {
			jwk = KEYS.rsaEnc;
		} else if (alg.startsWith("ECDH-ES")) {
			jwk = KEYS.ecEnc;
		} else {
			// symmetric key management (A128KW, dir, ...) is not supported by openid-client v6
			continue;
		}
		const { use: _use, alg: _alg, key_ops: _ops, ...material } = jwk;
		keys.push({ key: (await jose.importJWK(material, alg)) as client.CryptoKey, alg, kid: jwk.kid });
	}
	return keys;
}

// ---------------------------------------------------------------------------------------------------------------
// small helpers

class Deferred<T> {
	readonly promise: Promise<T>;
	resolve!: (value: T) => void;
	reject!: (reason: unknown) => void;
	settled = false;
	constructor() {
		this.promise = new Promise<T>((resolve, reject) => {
			this.resolve = (value) => {
				this.settled = true;
				resolve(value);
			};
			this.reject = (reason) => {
				this.settled = true;
				reject(reason);
			};
		});
		this.promise.catch(() => {});
	}
}

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
	let timer: NodeJS.Timeout | undefined;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms waiting for ${what}`)), ms);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function describeError(err: unknown): string {
	if (err instanceof Error) {
		const code = (err as { code?: string }).code;
		const oauthError = (err as { error?: string; error_description?: string }).error;
		const parts = [`${err.name}: ${err.message}`];
		if (code) {
			parts.push(`(${code})`);
		}
		if (oauthError) {
			parts.push(
				`[${oauthError}${(err as { error_description?: string }).error_description ? `: ${(err as { error_description?: string }).error_description}` : ""}]`,
			);
		}
		const cause = err.cause;
		if (cause instanceof URLSearchParams && cause.get("error")) {
			parts.push(`[${cause.get("error")}: ${cause.get("error_description") ?? ""}]`);
		}
		return parts.join(" ");
	}
	return String(err);
}

function norm(issuer: string): string {
	return issuer.replace(/\/$/, "");
}

function htmlSafe(value: unknown): string {
	return String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

function jsString(value: unknown): string {
	return JSON.stringify(value).replace(/</g, "\\u003c");
}

function page(title: string, body: string, head = ""): string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${htmlSafe(title)}</title>${head}</head><body>${body}</body></html>`;
}

function parseJsonParam<T>(value: string | null, fallback: T): T {
	if (!value) {
		return fallback;
	}
	return JSON.parse(value) as T;
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

const NEGATIVE_LOGIN_MODULES = new Set([
	"oidcc-client-test-invalid-iss",
	"oidcc-client-test-missing-sub",
	"oidcc-client-test-invalid-aud",
	"oidcc-client-test-missing-aud",
	"oidcc-client-test-missing-iat",
	"oidcc-client-test-kid-absent-multiple-jwks",
	"oidcc-client-test-userinfo-invalid-sub",
	"oidcc-client-test-nonce-invalid",
	"oidcc-client-test-missing-chash",
	"oidcc-client-test-invalid-chash",
	"oidcc-client-test-missing-athash",
	"oidcc-client-test-invalid-athash",
	"oidcc-client-test-invalid-sig-rs256",
]);

function moduleSpec(module: string): ModuleSpec {
	switch (module) {
		case "oidcc-client-test-form-post-error":
			return { kind: "login", params: { max_age: "0", prompt: "none" }, expectFailure: true };
		case "oidcc-client-test-scope-userinfo-claims":
			return {
				kind: "login",
				params: { scope: "openid email" },
				check: (r) => {
					const email = r.accessToken ? r.userinfo?.["email"] : r.claims?.["email"];
					if (!email) {
						throw new Error("email claim missing");
					}
				},
			};
		case "oidcc-client-test-aggregated-claims":
			return {
				kind: "login",
				params: { scope: "openid email" },
				check: (r) => {
					if (!r.userinfo?.["address"]) {
						throw new Error("aggregated address claim missing");
					}
				},
			};
		case "oidcc-client-test-distributed-claims":
			return {
				kind: "login",
				params: { scope: "openid email" },
				check: (r) => {
					if (r.userinfo?.["credit_score"] === undefined) {
						throw new Error("distributed credit_score claim missing");
					}
				},
			};
		case "oidcc-client-test-client-secret-basic":
			return { kind: "login", metadata: { token_endpoint_auth_method: "client_secret_basic" } };
		case "oidcc-client-test-idtoken-sig-none":
			return { kind: "login", metadata: { id_token_signed_response_alg: "none" } };
		case "oidcc-client-test-idtoken-sig-rs256":
			return { kind: "login", metadata: { id_token_signed_response_alg: "RS256" } };
		case "oidcc-client-test-invalid-sig-es256":
			return { kind: "login", metadata: { id_token_signed_response_alg: "ES256" }, expectFailure: true };
		case "oidcc-client-test-invalid-sig-hs256":
			return { kind: "login", metadata: { id_token_signed_response_alg: "HS256" }, expectFailure: true };
		case "oidcc-client-test-invalid-sig-rs256":
			return { kind: "login", metadata: { id_token_signed_response_alg: "RS256" }, expectFailure: true };
		case "oidcc-client-test-userinfo-bearer-body":
			return { kind: "login", userinfoVia: "body" };
		case "oidcc-client-test-userinfo-bearer-header":
			return { kind: "login", userinfoVia: "header" };
		case "oidcc-client-test-request-uri-signed-none":
			return { kind: "login", requestType: "request_uri", metadata: { request_object_signing_alg: "none" } };
		case "oidcc-client-test-request-uri-signed-rs256":
			return { kind: "login", requestType: "request_uri", metadata: { request_object_signing_alg: "RS256" } };
		case "oidcc-client-test-refresh-token":
			return { kind: "refresh", skipUserinfo: true };
		case "oidcc-client-test-refresh-token-invalid-issuer":
		case "oidcc-client-test-refresh-token-invalid-sub":
			return { kind: "refresh", skipUserinfo: true, expectFailure: true };
		case "oidcc-client-test-discovery-openid-config":
			return { kind: "discovery" };
		case "oidcc-client-test-discovery-jwks-uri-keys":
			return { kind: "jwks" };
		case "oidcc-client-test-discovery-webfinger-acct":
			return { kind: "webfinger-acct" };
		case "oidcc-client-test-discovery-webfinger-url":
			return { kind: "webfinger-url" };
		case "oidcc-client-test-discovery-issuer-mismatch":
			return { kind: "issuer-mismatch", expectFailure: true };
		case "oidcc-client-test-dynamic-registration":
			return { kind: "register" };
		case "oidcc-client-test-signing-key-rotation":
		case "oidcc-client-test-signing-key-rotation-just-before-signing":
			return { kind: "key-rotation" };
		case "oidcc-client-test-3rd-party-init-login":
			return { kind: "3rd-party" };
		case "oidcc-client-test-rp-init-logout":
		case "oidcc-client-test-rp-init-logout-other-state":
		case "oidcc-client-test-rp-init-logout-no-state":
		case "oidcc-client-test-rp-frontchannel-rpinitlogout":
			return { kind: "rp-logout" };
		case "oidcc-client-test-rp-backchannel-rpinitlogout":
			return { kind: "rp-logout", backchannel: "accept" };
		case "oidcc-client-test-rp-backchannel-rpinitlogout-alg-none":
		case "oidcc-client-test-rp-backchannel-rpinitlogout-no-event":
		case "oidcc-client-test-rp-backchannel-rpinitlogout-with-nonce":
		case "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-alg":
		case "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-aud":
		case "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-event":
		case "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-iss":
			return { kind: "rp-logout", backchannel: "reject" };
		case "oidcc-client-test-rp-frontchannel-opinitlogout":
			return { kind: "op-frontchannel-logout" };
		case "oidcc-client-test-session-management":
			return { kind: "session-management" };
		default:
			return { kind: "login", expectFailure: NEGATIVE_LOGIN_MODULES.has(module) };
	}
}

function isLogoutKind(kind: Kind): boolean {
	return kind === "rp-logout" || kind === "op-frontchannel-logout" || kind === "session-management";
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
	login: Deferred<LoginResult>;
	result?: LoginResult;
	loggedOut: Deferred<URLSearchParams>;
	frontchannel: Deferred<URLSearchParams>;
	backchannel: Deferred<{ accepted: boolean; error?: string }>;
	sessionCheck: Map<string, Deferred<string>>;
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

function step(flow: Flow | { steps: string[]; module: string }, message: string): void {
	flow.steps.push(message);
	console.log(`[rp] ${flow.module}: ${message}`);
}

// ---------------------------------------------------------------------------------------------------------------
// user agents: how the RP's "browser" follows front-channel redirects

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

/**
 * Minimal non-JS user agent: follows redirects, submits form_post auto-submit forms and delivers fragment
 * responses to /cb-fragment (what the /cb page's script does in a browser). Enough for the login modules.
 */
function fetchUserAgent(): UserAgent {
	// host -> cookie name -> value (enough for an OP's login/interaction cookies; attributes are ignored)
	const jar = new Map<string, Map<string, string>>();
	const withCookies = (target: URL, init: RequestInit): RequestInit => {
		const cookies = jar.get(target.host);
		if (!cookies?.size) {
			return init;
		}
		const headers = new Headers(init.headers);
		headers.set("cookie", [...cookies].map(([k, v]) => `${k}=${v}`).join("; "));
		return { ...init, headers };
	};
	const storeCookies = (target: URL, res: Response) => {
		for (const line of res.headers.getSetCookie()) {
			const [pair] = line.split(";");
			const eq = pair.indexOf("=");
			if (eq > 0) {
				const cookies = jar.get(target.host) ?? new Map<string, string>();
				cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
				jar.set(target.host, cookies);
			}
		}
	};
	return {
		async open(startUrl) {
			let url = startUrl;
			let init: RequestInit = { redirect: "manual" };
			for (let i = 0; i < 20; i++) {
				const target = new URL(url);
				if (target.hash && url.startsWith(REDIRECT_URI)) {
					url = `${BASE}/cb-fragment`;
					init = {
						redirect: "manual",
						method: "POST",
						headers: { "content-type": "application/x-www-form-urlencoded" },
						body: target.hash.slice(1),
					};
					continue;
				}
				target.hash = "";
				const res = await fetch(target, withCookies(target, init));
				storeCookies(target, res);
				const location = res.headers.get("location");
				if (res.status >= 300 && res.status < 400 && location) {
					url = new URL(location, target).href;
					init = { redirect: "manual" };
					continue;
				}
				const type = res.headers.get("content-type") ?? "";
				const body = await res.text();
				const formTag = type.includes("html") ? /<form\b[^>]*>/i.exec(body)?.[0] : undefined;
				const form = formTag && /method="post"/i.test(formTag) ? /action="([^"]+)"/i.exec(formTag) : null;
				if (form) {
					const params = new URLSearchParams();
					for (const m of body.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/gi)) {
						params.append(decodeEntities(m[1]), decodeEntities(m[2]));
					}
					url = new URL(decodeEntities(form[1]), target).href;
					init = {
						redirect: "manual",
						method: "POST",
						headers: { "content-type": "application/x-www-form-urlencoded" },
						body: params.toString(),
					};
					continue;
				}
				return;
			}
		},
		async close() {},
	};
}

function decodeEntities(s: string): string {
	return s
		.replace(/&quot;/g, '"')
		.replace(/&#39;|&#x27;/g, "'")
		.replace(/&lt;/g, "<")
		.replace(/&gt;/g, ">")
		.replace(/&#x2F;|&#47;/g, "/")
		.replace(/&#x3D;|&#61;/g, "=")
		.replace(/&amp;/g, "&");
}

async function createUserAgent(kind: Kind): Promise<UserAgent> {
	// logout / session modules render pages that only work with JavaScript (front-channel iframes, postMessage)
	if (process.env["RP_USER_AGENT"] === "fetch" && !isLogoutKind(kind)) {
		return fetchUserAgent();
	}
	return browserUserAgent();
}

// ---------------------------------------------------------------------------------------------------------------
// openid-client setup

function executeFor(issuer: string): ((config: client.Configuration) => void)[] {
	return new URL(issuer).protocol === "http:" ? [client.allowInsecureRequests] : [];
}

function grantTypesFor(responseType: string, refresh: boolean): string[] {
	const grants = new Set<string>();
	for (const t of responseType.split(" ")) {
		if (t === "code") {
			grants.add("authorization_code");
		} else if (t === "id_token" || t === "token") {
			grants.add("implicit");
		}
	}
	if (refresh) {
		grants.add("refresh_token");
	}
	return [...grants];
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
		...input.clientMetadataDefaults,
		token_endpoint_auth_method: authMethod,
		response_types: [responseType],
		grant_types: grantTypesFor(responseType, spec.kind === "refresh"),
		redirect_uris: [REDIRECT_URI],
		...spec.metadata,
	};
	if (isLogoutKind(spec.kind)) {
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
	configureResponseHandling(rp.config, responseType);
	await enableDecryption(rp.config);
	return rp;
}

function configureResponseHandling(config: client.Configuration, responseType: string): void {
	const types = new Set(responseType.split(" "));
	if (types.has("id_token") && types.has("code")) {
		client.useCodeIdTokenResponseType(config);
	} else if (types.has("id_token")) {
		client.useIdTokenResponseType(config);
	}
	// validate ID Token signatures from the token endpoint too (oidcc-client-test-invalid-sig-*, kid-absent-*)
	client.enableNonRepudiationChecks(config);
}

async function enableDecryption(config: client.Configuration): Promise<void> {
	const md = config.clientMetadata();
	const algs = [md.id_token_encrypted_response_alg, md.userinfo_encrypted_response_alg].filter(
		(a): a is string => typeof a === "string",
	);
	if (algs.length) {
		const keys = await decryptionKeys(algs);
		if (keys.length) {
			client.enableDecryptingResponses(config, undefined, ...keys);
		}
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
	configureResponseHandling(config, responseType);
	await enableDecryption(config);
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
		login: new Deferred(),
		loggedOut: new Deferred(),
		frontchannel: new Deferred(),
		backchannel: new Deferred(),
		sessionCheck: new Map([
			["before", new Deferred<string>()],
			["after", new Deferred<string>()],
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
		url.searchParams.set("request_uri", `${BASE}/request-object/${id}`);
		step(flow, `request object (alg ${alg}) hosted at ${BASE}/request-object/${id}`);
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
	}

	if (frontIdToken && frontAccessToken) {
		await validateAtHash(frontIdToken, frontAccessToken);
		step(flow, "at_hash validated");
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

async function handleAuthorizationResponse(params: URLSearchParams): Promise<{ status: number; html: string }> {
	const state = params.get("state");
	const flow = (state ? flowsByState.get(state) : undefined) ?? latestFlow;
	if (!flow) {
		return { status: 400, html: page("Error", "<h1>No login in progress</h1>") };
	}
	try {
		const result = await completeLogin(flow, params);
		flow.result = result;
		flow.loggedIn = true;
		flow.login.resolve(result);
		return {
			status: 200,
			html: page(
				"Signed in",
				`<h1 id="rp-login-complete">Signed in as ${htmlSafe(result.claims?.["sub"] ?? "?")}</h1>`,
			),
		};
	} catch (err) {
		step(flow, `authorization response rejected: ${describeError(err)}`);
		flow.login.reject(err);
		return {
			status: 400,
			html: page(
				"Login failed",
				`<h1 id="rp-login-failed">Login failed</h1><pre>${htmlSafe(describeError(err))}</pre>`,
			),
		};
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
	const steps: string[] = [];
	const ctx = { steps, module: input.module };
	step(
		ctx,
		`start (variant ${JSON.stringify(input.variant)}, metadata defaults ${JSON.stringify(input.clientMetadataDefaults)})`,
	);

	const expectRejection = async (fn: () => Promise<unknown>): Promise<StartResult> => {
		try {
			await fn();
			return {
				ok: false,
				error: "the RP did not reject the response",
				steps,
				module: input.module,
				outcome: "accepted",
			};
		} catch (err) {
			step(ctx, `rejected as expected: ${describeError(err)}`);
			return { ok: true, steps, module: input.module, outcome: "rejected", error: describeError(err) };
		}
	};

	const execute = executeFor(input.issuer);
	switch (spec.kind) {
		case "discovery": {
			const config = await client.discovery(new URL(input.issuer), "discovery-only", undefined, client.None(), {
				execute,
			});
			step(ctx, `discovered ${config.serverMetadata().issuer}`);
			return { ok: true, steps, module: input.module };
		}
		case "jwks": {
			const config = await client.discovery(new URL(input.issuer), "discovery-only", undefined, client.None(), {
				execute,
			});
			step(ctx, `discovered ${config.serverMetadata().issuer}`);
			const res = await fetch(config.serverMetadata().jwks_uri!);
			const jwks = (await res.json()) as jose.JSONWebKeySet;
			jose.createLocalJWKSet(jwks);
			step(ctx, `fetched jwks_uri with ${jwks.keys.length} keys`);
			return { ok: true, steps, module: input.module };
		}
		case "webfinger-acct":
		case "webfinger-url":
		case "issuer-mismatch": {
			const issuerUrl = new URL(input.issuer);
			let resource: string;
			if (spec.kind === "webfinger-acct") {
				const alias = input.alias ?? issuerUrl.pathname.replace(/^\/test\/a\//, "").replace(/\/$/, "");
				resource = `acct:${alias}.${input.module}@${issuerUrl.host}`;
			} else {
				resource = `${input.issuer}${input.module}`;
			}
			const flowFn = async () => {
				const href = await webfinger(resource, issuerUrl.protocol);
				step(ctx, `webfinger ${resource} -> ${href}`);
				const config = await client.discovery(new URL(href), "discovery-only", undefined, client.None(), { execute });
				step(ctx, `discovered ${config.serverMetadata().issuer}`);
			};
			if (spec.expectFailure) {
				return expectRejection(flowFn);
			}
			await flowFn();
			return { ok: true, steps, module: input.module };
		}
		case "register": {
			await setUpClient(ctx, input, spec);
			return { ok: true, steps, module: input.module };
		}
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
			return { ok: true, steps, module: input.module, outcome: `signed in as ${String(result.claims?.["sub"])}` };
		} finally {
			flow.waitingForInitiateLogin = false;
		}
	}

	const ua = await createUserAgent(spec.kind);
	try {
		// the user agent starts at the RP's /login (like a login button), which redirects to the OP
		const login = async (target = flow) => {
			await ua.open(`${BASE}/login?flow=${target.id}`);
			return withTimeout(target.login.promise, LOGIN_TIMEOUT_MS, "the authorization response");
		};

		if (spec.kind === "login") {
			if (spec.expectFailure) {
				return await expectRejection(() => login());
			}
			await login();
			return { ok: true, steps, module: input.module, outcome: "signed in" };
		}

		if (spec.kind === "refresh") {
			const result = await login();
			if (!result.refreshToken) {
				throw new Error("no refresh_token was issued");
			}
			const doRefresh = async () => {
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
			};
			if (spec.expectFailure) {
				return await expectRejection(doRefresh);
			}
			await doRefresh();
			return { ok: true, steps, module: input.module, outcome: "refreshed" };
		}

		if (spec.kind === "key-rotation") {
			await login();
			// second authentication with a configuration that has no cached JWKS, so the rotated key is fetched
			const second = newFlow(
				input,
				spec,
				{ ...rp, config: await freshConfig(rp, flow.responseType, input.issuer) },
				steps,
			);
			step(flow, "second authentication after OP key rotation");
			await login(second);
			return { ok: true, steps, module: input.module, outcome: "signed in twice" };
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
			return { ok: true, steps, module: input.module, outcome: "logged out (front-channel)" };
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
				return {
					ok: false,
					error: `expected the logout_token to be ${spec.backchannel}ed but it was ${accepted}`,
					steps,
					module: input.module,
				};
			}
		}

		if (spec.kind === "session-management") {
			await sessionCheck(flow, ua, "after", "changed");
		}
		return { ok: true, steps, module: input.module, outcome: "logged out" };
	} finally {
		await ua.close();
	}
}

async function sessionCheck(flow: Flow, ua: UserAgent, phase: "before" | "after", expected: string): Promise<void> {
	const deferred = flow.sessionCheck.get(phase)!;
	await ua.open(`${BASE}/session-check?flow=${flow.id}&phase=${phase}`);
	const result = await withTimeout(deferred.promise, 15_000, `the check_session_iframe answer (${phase} logout)`);
	step(flow, `check_session_iframe ${phase} logout: ${result}`);
	if (result !== expected) {
		throw new Error(`check_session_iframe answered "${result}" ${phase} logout, expected "${expected}"`);
	}
}

async function webfinger(resource: string, protocol: string): Promise<string> {
	let origin: string;
	if (resource.startsWith("acct:")) {
		const host = resource.slice(resource.lastIndexOf("@") + 1);
		origin = `${protocol}//${host}`;
	} else {
		origin = new URL(resource).origin;
	}
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

		case "GET /start": {
			let input: StartInput;
			try {
				const issuer = q.get("issuer");
				const module = q.get("module");
				if (!issuer || !module) {
					return sendJson(res, 400, { ok: false, error: "issuer and module query parameters are required", steps: [] });
				}
				input = {
					issuer,
					module,
					variant: parseJsonParam(q.get("variant"), {}),
					clientMetadataDefaults: parseJsonParam(q.get("client_metadata_defaults"), {}),
					alias: q.get("alias") ?? undefined,
					clientId: q.get("client_id") ?? undefined,
					clientSecret: q.get("client_secret") ?? undefined,
					jwks: parseJsonParam<{ keys: jose.JWK[] } | undefined>(q.get("jwks"), undefined),
				};
			} catch (err) {
				return sendJson(res, 400, { ok: false, error: describeError(err), steps: [] });
			}
			let result: StartResult;
			try {
				result = await runModule(input);
			} catch (err) {
				console.log(`[rp] ${input.module}: failed: ${describeError(err)}`);
				result = { ok: false, error: describeError(err), steps: [], module: input.module };
			}
			if (!result.steps.length) {
				result.steps = [...(latestFlow?.module === input.module ? latestFlow.steps : [])];
			}
			console.log(`[rp] ${input.module}: ${result.ok ? "OK" : "NOT OK"}${result.error ? ` - ${result.error}` : ""}`);
			return sendJson(res, 200, result);
		}

		case "GET /login": {
			const flow = flows.get(q.get("flow") ?? "");
			if (!flow) {
				return send(res, 404, page("Error", "<h1>unknown login</h1>"));
			}
			const target = await buildAuthorizationUrl(flow);
			step(flow, `authorization request ${target.href.length > 300 ? `${target.href.slice(0, 300)}...` : target.href}`);
			return redirect(res, target.href);
		}

		case "GET /cb": {
			if (!url.search) {
				return send(res, 200, FRAGMENT_PAGE);
			}
			const { status, html } = await handleAuthorizationResponse(q);
			return send(res, status, html);
		}

		case "POST /cb":
		case "POST /cb-fragment": {
			const params = new URLSearchParams(await readBody(req));
			const { status, html } = await handleAuthorizationResponse(params);
			return send(res, status, html);
		}

		case "GET /logout": {
			const flow = flows.get(q.get("flow") ?? "");
			if (!flow?.result?.idToken) {
				return send(res, 400, page("Error", "<h1>not signed in</h1>"));
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
			const flow =
				[...flows.values()].find((f) => f.endSessionState && f.endSessionState === state) ??
				[...flows.values()].filter((f) => f.endSessionState).at(-1);
			if (flow) {
				flow.loggedIn = false;
				flow.loggedOut.resolve(q);
			}
			return send(res, 200, page("Signed out", '<h1 id="rp-logged-out">Signed out</h1>'));
		}

		case "POST /backchannel-logout": {
			const body = new URLSearchParams(await readBody(req));
			const logoutToken = body.get("logout_token");
			let flow: Flow | undefined;
			try {
				if (!logoutToken) {
					throw new Error("logout_token missing");
				}
				let aud: unknown;
				let sid: unknown;
				try {
					const claims = jose.decodeJwt(logoutToken);
					aud = claims.aud;
					sid = claims["sid"];
				} catch {
					// validated below
				}
				flow = findFlowForLogout((f) => (sid !== undefined && f.sid === sid) || f.rp.clientId === aud);
				if (!flow) {
					throw new Error("no session for this logout_token");
				}
				await validateLogoutToken(flow, logoutToken);
				flow.loggedIn = false;
				step(flow, "back-channel logout_token accepted, session cleared");
				flow.backchannel.resolve({ accepted: true });
				return send(res, 200, "", { "content-type": "text/plain" });
			} catch (err) {
				const error = describeError(err);
				if (flow) {
					step(flow, `back-channel logout_token rejected: ${error}`);
					flow.backchannel.resolve({ accepted: false, error });
				} else {
					latestFlow?.backchannel.resolve({ accepted: false, error });
				}
				return sendJson(res, 400, { error: "invalid_request", error_description: error });
			}
		}

		case "GET /frontchannel-logout": {
			const iss = q.get("iss");
			const sid = q.get("sid");
			const flow = findFlowForLogout(
				(f) => (!sid || f.sid === sid) && (!iss || f.rp.config.serverMetadata().issuer === iss),
			);
			if (flow) {
				flow.loggedIn = false;
				step(flow, `front-channel logout received (iss ${iss ?? "-"}, sid ${sid ?? "-"}), session cleared`);
				flow.frontchannel.resolve(q);
			}
			return send(res, 200, page("Signed out", "<p>Signed out</p>"));
		}

		case "GET /session-check": {
			const flow = flows.get(q.get("flow") ?? "");
			if (!flow) {
				return send(res, 404, page("Error", "<h1>unknown session</h1>"));
			}
			return send(res, 200, sessionCheckPage(flow, q.get("phase") ?? "before"));
		}

		case "GET /session-status": {
			const flow = flows.get(q.get("flow") ?? "");
			flow?.sessionCheck.get(q.get("phase") ?? "")?.resolve(q.get("result") ?? "");
			return sendJson(res, 200, { ok: !!flow });
		}

		case "GET /initiate-login": {
			// OIDC Core 4: third party initiated login (iss, login_hint, target_link_uri)
			const iss = q.get("iss") ?? "";
			const flow = [...flows.values()]
				.filter((f) => f.waitingForInitiateLogin && norm(f.rp.config.serverMetadata().issuer) === norm(iss))
				.at(-1);
			if (!flow) {
				return send(res, 400, page("Error", `<h1>unknown issuer ${htmlSafe(iss)}</h1>`));
			}
			step(flow, `initiate_login_uri called (iss ${iss})`);
			const extra: Record<string, string> = {};
			if (q.get("login_hint")) {
				extra["login_hint"] = q.get("login_hint")!;
			}
			const target = await buildAuthorizationUrl(flow, extra);
			step(flow, `authorization request ${target.href.length > 300 ? `${target.href.slice(0, 300)}...` : target.href}`);
			return redirect(res, target.href);
		}

		default:
			break;
	}

	if (req.method === "GET" && url.pathname.startsWith("/request-object/")) {
		const jwt = requestObjects.get(url.pathname.slice("/request-object/".length));
		if (!jwt) {
			return send(res, 404, "not found", { "content-type": "text/plain" });
		}
		return send(res, 200, jwt, { "content-type": "application/oauth-authz-req+jwt" });
	}

	return send(res, 404, page("Not found", "<h1>not found</h1>"));
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

/** self-signed certificate for the https listener (initiate_login_uri must be https, ValidateClientInitiateLoginUri) */
function selfSignedCertificate(): { key: string; cert: string } | undefined {
	const dir = mkdtempSync(join(tmpdir(), "rp-tls-"));
	try {
		execFileSync(
			"openssl",
			[
				"req",
				"-x509",
				"-newkey",
				"rsa:2048",
				"-nodes",
				"-days",
				"2",
				"-subj",
				"/CN=localhost",
				"-addext",
				"subjectAltName=DNS:localhost,IP:127.0.0.1",
				"-keyout",
				join(dir, "key.pem"),
				"-out",
				join(dir, "cert.pem"),
			],
			{ stdio: "ignore" },
		);
		return { key: readFileSync(join(dir, "key.pem"), "utf8"), cert: readFileSync(join(dir, "cert.pem"), "utf8") };
	} catch (err) {
		console.warn(
			`[rp] could not create a self-signed certificate with openssl (${describeError(err)}), https disabled`,
		);
		return undefined;
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

export interface RunningRp {
	base: string;
	close(): Promise<void>;
}

export async function start(): Promise<RunningRp> {
	await initKeys();
	const servers: Server[] = [];
	const http = createServer(handler);
	await new Promise<void>((resolve, reject) => {
		http.once("error", reject);
		http.listen(PORT, "localhost", () => resolve());
	});
	servers.push(http);
	if (HTTPS_PORT) {
		const tls = selfSignedCertificate();
		if (tls) {
			const https = createHttpsServer(tls, handler);
			await new Promise<void>((resolve, reject) => {
				https.once("error", reject);
				https.listen(HTTPS_PORT, "localhost", () => resolve());
			});
			servers.push(https);
		}
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
	const shutdown = () => {
		void running.close().then(() => process.exit(0));
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
