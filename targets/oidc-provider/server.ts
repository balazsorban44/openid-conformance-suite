/**
 * OpenID Provider under test for the OP plans: panva's oidc-provider, configured the way upstream's CI configures its
 * `oidcc-provider` service (docker image panvafs/oidc-provider-oidc-core-sample, i.e.
 * https://github.com/panva/node-oidc-provider/tree/main/certification/oidc) with the differences needed to run on
 * plain http://localhost and to cover what oidc-provider v9 no longer ships (front-channel logout, session
 * management, request_uri by reference).
 *
 *   node targets/oidc-provider/server.ts            # PORT (default 3000), ISSUER (default http://localhost:PORT)
 *
 * Environment:
 *   PORT, ISSUER                      listen port / issuer identifier
 *   OIDC_PROVIDER_CLIENTS             JSON array of static client metadata (overrides clients.json)
 *   OIDC_PROVIDER_CLIENTS_FILE        path to a JSON file with static clients (default targets/oidc-provider/clients.json)
 *   OIDC_PROVIDER_JWKS                private JWKS JSON to use instead of keys generated at startup
 *   OIDC_PROVIDER_AUTO_APPROVE=1      self-test mode for the RP target: no login/consent/logout user interaction
 *   DEBUG_OIDC_PROVIDER=1             log every request and provider error
 */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createNetServer, type AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import * as querystring from "node:querystring";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from "jose";
import Provider, { errors } from "oidc-provider";
import { defaults } from "oidc-provider/lib/helpers/defaults.js";
import * as jwa from "oidc-provider/lib/consts/jwa.js";

// oidc-provider has no type declarations, its objects are handled untyped
// oxlint-disable-next-line typescript/no-explicit-any
type Any = any;

export interface StartOptions {
	/** listen port, default PORT env or 3000; 0 picks a free port */
	port?: number;
	/** listen host, default "localhost" */
	host?: string;
	/** issuer identifier, default ISSUER env or http://localhost:<port> */
	issuer?: string;
	/** static clients, default OIDC_PROVIDER_CLIENTS env / clients.json */
	clients?: Record<string, unknown>[];
	/** private JWKS, default OIDC_PROVIDER_JWKS env / generated */
	jwks?: { keys: JWK[] };
	/** log requests and errors */
	debug?: boolean;
	/**
	 * Self-test mode for the RP target (OIDC_PROVIDER_AUTO_APPROVE=1): login (as "foo"), consent and the logout
	 * confirmation complete without user interaction. Never used for the OP plans.
	 */
	autoApprove?: boolean;
}

export interface RunningProvider {
	issuer: string;
	readyUrl: string;
	provider: Any;
	server: Server;
	close(): Promise<void>;
}

const HERE = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_PORT = 3000;

/** The URL the CI runner polls before starting a plan: issuer + /.well-known/openid-configuration */
export function readyUrl(issuer = `http://localhost:${process.env["PORT"] ?? DEFAULT_PORT}`): string {
	return `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
}

/** Test account (any login/password is accepted at the login form, the login value becomes the sub). */
const ACCOUNT_CLAIMS = {
	name: "Foo Bar",
	given_name: "Foo",
	family_name: "Bar",
	middle_name: "Baz",
	nickname: "foobar",
	preferred_username: "foo",
	profile: "https://example.com/foo",
	picture: "https://example.com/foo.png",
	website: "https://example.com/",
	email: "foo@example.com",
	email_verified: true,
	gender: "female",
	birthdate: "1987-10-16",
	zoneinfo: "Europe/Prague",
	locale: "en-US",
	phone_number: "+15555550100",
	phone_number_verified: false,
	address: {
		formatted: "1 Main Street\nAnytown, AS 12345\nUS",
		street_address: "1 Main Street",
		locality: "Anytown",
		region: "AS",
		postal_code: "12345",
		country: "US",
	},
	updated_at: 1_700_000_000,
};

/** acr value the login interaction always asserts (same as upstream's certification config) */
const ACR = "urn:mace:incommon:iap:bronze";

/** cookie holding the OP browser state for OpenID Connect Session Management (readable by check_session_iframe JS) */
const OPBS_COOKIE = "op_browser_state";

/** static clients may use any suite redirect URI on the loopback host (the suite port is dynamic) */
const STATIC_REDIRECT_URI = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/test\/(a\/[^/?#]+|[^/?#]+)\/callback$/;
const STATIC_POST_LOGOUT_REDIRECT_URI =
	/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/test\/(a\/[^/?#]+|[^/?#]+)\/post_logout_redirect$/;

function loadStaticClients(): Record<string, unknown>[] {
	if (process.env["OIDC_PROVIDER_CLIENTS"]) {
		return JSON.parse(process.env["OIDC_PROVIDER_CLIENTS"]);
	}
	const file = process.env["OIDC_PROVIDER_CLIENTS_FILE"] ?? `${HERE}clients.json`;
	return JSON.parse(readFileSync(file, "utf8"));
}

async function generateJwks(): Promise<{ keys: JWK[] }> {
	const specs: [string, { use: string; crv?: string; modulusLength?: number }][] = [
		["RS256", { use: "sig", modulusLength: 2048 }],
		["RSA-OAEP", { use: "enc", modulusLength: 2048 }],
		["ES256", { use: "sig" }],
		["ECDH-ES", { use: "enc", crv: "P-256" }],
		["ES384", { use: "sig" }],
		["ES512", { use: "sig" }],
		["Ed25519", { use: "sig" }],
		["ECDH-ES", { use: "enc", crv: "X25519" }],
	];
	const keys: JWK[] = [];
	for (const [alg, { use, ...options }] of specs) {
		const { privateKey } = await generateKeyPair(alg, { ...options, extractable: true });
		const jwk = await exportJWK(privateKey);
		jwk.use = use;
		jwk.kid = await calculateJwkThumbprint(jwk);
		keys.push(jwk);
	}
	return { keys };
}

function noPq(algs: string[]): string[] {
	return algs.filter((alg) => !alg.startsWith("ML-DSA"));
}

function sha256url(input: string): string {
	return createHash("sha256").update(input).digest("base64url");
}

/** OIDC Session Management 1.0 section 3: session_state = hash(client_id origin opbs salt) + "." + salt */
function sessionState(clientId: string, origin: string, opbs: string, salt: string): string {
	return `${sha256url(`${clientId} ${origin} ${opbs} ${salt}`)}.${salt}`;
}

function htmlSafe(value: unknown): string {
	return String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

/** check_session_iframe page (OIDC Session Management 1.0 section 3.3), recomputes session_state from the cookie */
function checkSessionIframeHtml(): string {
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>check_session_iframe</title></head>
<body>
<script>
function opbs() {
	var m = document.cookie.match(/(?:^|; )${OPBS_COOKIE}=([^;]*)/);
	return m ? decodeURIComponent(m[1]) : "";
}
function b64url(buf) {
	var s = String.fromCharCode.apply(null, new Uint8Array(buf));
	return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
}
window.addEventListener("message", function (e) {
	if (typeof e.data !== "string") return;
	var parts = e.data.split(" ");
	if (parts.length !== 2 || parts[1].indexOf(".") === -1) {
		e.source.postMessage("error", e.origin);
		return;
	}
	var clientId = parts[0];
	var ss = parts[1];
	var salt = ss.substring(ss.lastIndexOf(".") + 1);
	if (!window.crypto || !window.crypto.subtle) {
		e.source.postMessage("error", e.origin);
		return;
	}
	var data = new TextEncoder().encode(clientId + " " + e.origin + " " + opbs() + " " + salt);
	crypto.subtle.digest("SHA-256", data).then(function (digest) {
		var expected = b64url(digest) + "." + salt;
		e.source.postMessage(expected === ss ? "unchanged" : "changed", e.origin);
	}, function () {
		e.source.postMessage("error", e.origin);
	});
}, false);
</script>
</body></html>`;
}

/** page rendered after end_session confirmation that loads every frontchannel_logout_uri, then continues */
function frontchannelLogoutHtml(frames: string[], continueTo: string): string {
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signing out</title>
<script>
var pending = ${frames.length};
var done = false;
function next() {
	if (done) return;
	done = true;
	window.location.replace(${JSON.stringify(continueTo).replace(/</g, "\\u003c")});
}
function loaded() {
	pending -= 1;
	if (pending <= 0) setTimeout(next, 250);
}
setTimeout(next, 5000);
</script>
</head>
<body>
<p>Signing out of ${frames.length} application(s)...</p>
${frames.map((src) => `<iframe src="${htmlSafe(src)}" onload="loaded()" hidden></iframe>`).join("\n")}
</body></html>`;
}

export async function start(opts: StartOptions = {}): Promise<RunningProvider> {
	let port = opts.port ?? Number(process.env["PORT"] ?? DEFAULT_PORT);
	if (port === 0) {
		port = await freePort();
	}
	const host = opts.host ?? "localhost";
	const debug = opts.debug ?? process.env["DEBUG_OIDC_PROVIDER"] === "1";
	const autoApprove = opts.autoApprove ?? process.env["OIDC_PROVIDER_AUTO_APPROVE"] === "1";
	const staticClients = opts.clients ?? loadStaticClients();
	const staticClientIds = new Set(staticClients.map((c) => String(c["client_id"])));
	const jwks =
		opts.jwks ??
		(process.env["OIDC_PROVIDER_JWKS"] ? JSON.parse(process.env["OIDC_PROVIDER_JWKS"]) : null) ??
		(await generateJwks());

	// OIDC_PROVIDER_TLS_CERT / OIDC_PROVIDER_TLS_KEY (PEM file paths) serve https (the suite requires https for
	// registration_client_uri, initiate_login_uri, sector_identifier_uri ...)
	const tls =
		process.env["OIDC_PROVIDER_TLS_CERT"] && process.env["OIDC_PROVIDER_TLS_KEY"]
			? {
					cert: readFileSync(process.env["OIDC_PROVIDER_TLS_CERT"], "utf8"),
					key: readFileSync(process.env["OIDC_PROVIDER_TLS_KEY"], "utf8"),
				}
			: null;
	const issuer = (opts.issuer ?? process.env["ISSUER"] ?? `${tls ? "https" : "http"}://localhost:${port}`).replace(
		/\/$/,
		"",
	);

	// ML-DSA is filtered out like upstream's CI (conformance-suite#1598); everything else oidc-provider implements is
	// enabled so the suite can register clients with any id_token/userinfo/request object alg it wants to test
	const enabledJWA = {
		clientAuthSigningAlgValues: noPq(jwa.clientAuthSigningAlgValues),
		idTokenSigningAlgValues: noPq(jwa.idTokenSigningAlgValues),
		requestObjectSigningAlgValues: noPq(jwa.requestObjectSigningAlgValues),
		userinfoSigningAlgValues: noPq(jwa.userinfoSigningAlgValues),
		introspectionSigningAlgValues: noPq(jwa.introspectionSigningAlgValues),
		authorizationSigningAlgValues: noPq(jwa.authorizationSigningAlgValues),
		idTokenEncryptionAlgValues: jwa.idTokenEncryptionAlgValues,
		requestObjectEncryptionAlgValues: jwa.requestObjectEncryptionAlgValues,
		userinfoEncryptionAlgValues: jwa.userinfoEncryptionAlgValues,
		introspectionEncryptionAlgValues: jwa.introspectionEncryptionAlgValues,
		authorizationEncryptionAlgValues: jwa.authorizationEncryptionAlgValues,
		idTokenEncryptionEncValues: jwa.idTokenEncryptionEncValues,
		requestObjectEncryptionEncValues: jwa.requestObjectEncryptionEncValues,
		userinfoEncryptionEncValues: jwa.userinfoEncryptionEncValues,
		introspectionEncryptionEncValues: jwa.introspectionEncryptionEncValues,
		authorizationEncryptionEncValues: jwa.authorizationEncryptionEncValues,
	};

	// front-channel logout iframes pending per logout confirmation (keyed by the end_session xsrf secret)
	const pendingFrontchannel = new Map<string, { clientId?: string; frames: { clientId: string; url: string }[] }>();

	const defaultLogoutSource = defaults.features.rpInitiatedLogout.logoutSource;

	const configuration = {
		clients: staticClients,
		jwks,
		cookies: { keys: [randomBytes(32).toString("base64url")] },
		// oidcc-* "Login"/"Consent" browser tasks: devInteractions renders the login form with name="login",
		// name="password" and a .login-submit button (title "Sign-in"), and the consent form with a .login-submit
		// button, exactly the pages upstream's browser configuration and screenshots expect. Any login/password works.
		features: {
			devInteractions: { enabled: true },
			// oidcc-claims-* / oidcc-*-essential: claims request parameter
			claimsParameter: { enabled: true },
			// oidcc-dynamic-certification-test-plan, all dynamic_client variants: open registration without IAT
			registration: { enabled: true, initialAccessToken: false },
			registrationManagement: { enabled: true, rotateRegistrationAccessToken: true },
			// oidcc-request-*, oidcc-unsigned-request-object-*, oidcc-ensure-request-object-*: request parameter
			requestObjects: { enabled: true, requireSignedRequestObject: false },
			// oidcc-idtoken-*-encrypted, oidcc-userinfo-*: id_token / userinfo encryption when the client registers it
			encryption: { enabled: true },
			// userinfo_signed_response_alg support
			jwtUserinfo: { enabled: true },
			introspection: { enabled: true },
			revocation: { enabled: true },
			clientCredentials: { enabled: true },
			// oidcc-backchannel-rp-initiated-logout-certification-test-plan
			backchannelLogout: { enabled: true },
			// oidcc-rp-initiated-logout-certification-test-plan (and the other logout plans). logoutSource keeps the
			// default page (button[autofocus] = "Yes, sign me out", used by the upstream browser task) and records
			// which frontchannel_logout_uri iframes to render once the user confirms (oidcc-frontchannel-*).
			rpInitiatedLogout: {
				enabled: true,
				async logoutSource(ctx: Any, form: string) {
					const session = ctx.oidc.session;
					const frames: { clientId: string; url: string }[] = [];
					for (const clientId of Object.keys(session.authorizations ?? {})) {
						const client = await ctx.oidc.provider.Client.find(clientId).catch(() => undefined);
						const uri = client?.metadata()["frontchannel_logout_uri"];
						if (!uri) {
							continue;
						}
						const url = new URL(uri);
						url.searchParams.set("iss", issuer);
						url.searchParams.set("sid", session.sidFor(clientId));
						frames.push({ clientId, url: url.href });
					}
					if (frames.length) {
						pendingFrontchannel.set(session.state.secret, { clientId: session.state.clientId, frames });
					}
					await defaultLogoutSource(ctx, form);
					if (autoApprove) {
						ctx.body = String(ctx.body).replace(
							"</body>",
							'<script>document.querySelector("button[autofocus]").click()</script></body>',
						);
					}
				},
			},
		},
		// OIDC Front-Channel Logout 1.0 client metadata (oidc-provider v9 dropped the feature, re-added here)
		extraClientMetadata: {
			properties: ["frontchannel_logout_uri", "frontchannel_logout_session_required"],
			validator(_ctx: Any, key: string, value: unknown) {
				if (key === "frontchannel_logout_uri" && value !== undefined) {
					if (typeof value !== "string" || !URL.canParse(value) || !/^https?:$/.test(new URL(value).protocol)) {
						throw new errors.InvalidClientMetadata("frontchannel_logout_uri must be a web uri");
					}
				}
				if (key === "frontchannel_logout_session_required" && value !== undefined && typeof value !== "boolean") {
					throw new errors.InvalidClientMetadata("frontchannel_logout_session_required must be a boolean");
				}
			},
		},
		claims: {
			amr: null,
			address: ["address"],
			email: ["email", "email_verified"],
			phone: ["phone_number", "phone_number_verified"],
			profile: [
				"birthdate",
				"family_name",
				"gender",
				"given_name",
				"locale",
				"middle_name",
				"name",
				"nickname",
				"picture",
				"preferred_username",
				"profile",
				"updated_at",
				"website",
				"zoneinfo",
			],
		},
		scopes: ["openid", "offline_access", "profile", "email", "address", "phone"],
		// oidcc-ensure-request-with-acr-values-succeeds, oidcc-id-token-acr-*: acr_values_supported
		acrValues: [ACR],
		responseTypes: ["code id_token token", "code id_token", "code token", "code", "id_token token", "id_token", "none"],
		subjectTypes: ["public", "pairwise"],
		pairwiseIdentifier(_ctx: Any, accountId: string, { sectorIdentifier }: { sectorIdentifier: string }) {
			return createHash("sha256")
				.update(sectorIdentifier)
				.update(accountId)
				.update("oidc-provider-target")
				.digest("hex");
		},
		clientAuthMethods: ["none", "client_secret_basic", "client_secret_jwt", "client_secret_post", "private_key_jwt"],
		enabledJWA,
		// PKCE is optional (the OIDC plans only send it in some modules)
		pkce: { required: () => false },
		// oidcc-ensure-redirect-uri-in-authorization-request: redirect_uri is REQUIRED in OIDC, even with one registered
		allowOmittingSingleRegisteredRedirectUri: false,
		// oidcc-refresh-token / oidcc-refresh-token-rp-key-rotation: refresh tokens for offline_access (same rule as
		// upstream's certification config)
		async issueRefreshToken(_ctx: Any, client: Any, code: Any) {
			if (!client.grantTypeAllowed("refresh_token")) {
				return false;
			}
			return (
				code.scopes.has("offline_access") || (client.applicationType === "web" && client.clientAuthMethod === "none")
			);
		},
		async findAccount(_ctx: Any, sub: string) {
			return {
				accountId: sub,
				async claims() {
					return { sub, ...structuredClone(ACCOUNT_CLAIMS) };
				},
			};
		},
		ttl: {
			RegistrationAccessToken: 24 * 60 * 60,
		},
		renderError: defaults.renderError,
		// outgoing requests (backchannel_logout_uri, jwks_uri, sector_identifier_uri, request_uri) go to the suite on
		// localhost; oidc-provider's default dispatcher refuses loopback/private addresses, so use plain fetch like
		// upstream's certification config does for oidcc-dynamic-* and oidcc-backchannel-rp-initiated-logout
		fetch(url: URL | string, options: RequestInit & { dispatcher?: unknown }) {
			delete options.dispatcher;
			return globalThis.fetch(url, options);
		},
	};

	const provider = new Provider(issuer, configuration);

	// the suite runs on http://localhost: allow implicit/hybrid clients to register http and localhost redirect_uris
	// (oidcc-implicit-*, oidcc-hybrid-* plans and every logout plan with response_type including id_token)
	const { invalidate } = provider.Client.Schema.prototype;
	provider.Client.Schema.prototype.invalidate = function (message: string, code?: string) {
		if (code === "implicit-force-https" || code === "implicit-forbid-localhost") {
			return;
		}
		return invalidate.call(this, message, code);
	};

	// static_client variants: the suite's redirect_uri contains its dynamic port, accept any suite callback URL on
	// the loopback host for the static clients (still exact-path, so oidcc-ensure-registered-redirect-uri fails)
	const { redirectUriAllowed, postLogoutRedirectUriAllowed } = provider.Client.prototype;
	provider.Client.prototype.redirectUriAllowed = function (value: string) {
		if (staticClientIds.has(this.clientId) && STATIC_REDIRECT_URI.test(value)) {
			return true;
		}
		return redirectUriAllowed.call(this, value);
	};
	provider.Client.prototype.postLogoutRedirectUriAllowed = function (value: string) {
		if (staticClientIds.has(this.clientId) && STATIC_POST_LOGOUT_REDIRECT_URI.test(value)) {
			return true;
		}
		return postLogoutRedirectUriAllowed.call(this, value);
	};

	// oidcc-frontchannel-rp-initiated-logout (CheckIdTokenSidMatchesFrontChannelLogoutRequest) and the back-channel
	// logout plan compare the sid of the ID Token with the logout request: always include sid in ID Tokens
	provider.Client.prototype.includeSid = () => true;

	// oidcc-ensure-request-with-acr-values-succeeds etc.: like upstream, assert a static acr/amr on every login
	const { interactionFinished } = provider;
	provider.interactionFinished = (...args: Any[]) => {
		const { login } = args[2];
		if (login) {
			Object.assign(args[2].login, { acr: ACR, amr: ["pwd"] });
		}
		return interactionFinished.call(provider, ...args);
	};

	// OIDC Session Management 1.0: add session_state to every successful authorization response and keep the OP
	// browser state cookie in sync (oidcc-session-management-certification-test-plan)
	provider.on("authorization.success", (ctx: Any, out: Record<string, unknown>) => {
		const session = ctx.oidc.session;
		const client = ctx.oidc.client;
		const redirectUri = ctx.oidc.params?.redirect_uri;
		if (!session?.accountId || !client || !redirectUri || !URL.canParse(redirectUri)) {
			return;
		}
		const opbs = sha256url(`${session.uid}:${session.loginTs ?? ""}`);
		ctx.cookies.set(OPBS_COOKIE, opbs, { httpOnly: false, sameSite: "lax", path: "/", overwrite: true, signed: false });
		const salt = randomBytes(8).toString("base64url");
		out["session_state"] = sessionState(client.clientId, new URL(redirectUri).origin, opbs, salt);
	});

	if (debug) {
		provider.on("server_error", (_ctx: Any, err: Error) => console.error("server_error", err));
		provider.on("authorization.error", (_ctx: Any, err: Error) => console.error("authorization.error", err.message));
		provider.on("grant.error", (_ctx: Any, err: Error) => console.error("grant.error", err.message));
		provider.on("backchannel.error", (_ctx: Any, err: Error) => console.error("backchannel.error", err.message));
	}

	provider.use(async (ctx: Any, next: () => Promise<void>) => {
		if (debug) {
			console.log(ctx.method, ctx.url);
		}

		if (autoApprove && ctx.method === "GET" && ctx.path.startsWith("/interaction/")) {
			await autoApproveInteraction(provider, ctx);
			return;
		}

		// check_session_iframe (oidcc-session-management-*)
		if (ctx.method === "GET" && ctx.path === "/session/check") {
			ctx.type = "html";
			ctx.set("cache-control", "no-store");
			ctx.body = checkSessionIframeHtml();
			return;
		}

		// request_uri by reference (oidcc-request-uri-unsigned, oidcc-request-uri-signed-*): oidc-provider v9 only
		// supports PAR request_uris, so dereference http(s) request_uris here and pass the object on as `request`
		if (ctx.path === "/auth" && (ctx.method === "GET" || ctx.method === "POST")) {
			await dereferenceRequestUri(ctx);
		}

		await next();

		// discovery additions for the features implemented in this file
		if (ctx.path === "/.well-known/openid-configuration" && ctx.status === 200 && ctx.body) {
			Object.assign(ctx.body, {
				request_uri_parameter_supported: true,
				require_request_uri_registration: false,
				frontchannel_logout_supported: true,
				frontchannel_logout_session_supported: true,
				check_session_iframe: `${issuer}/session/check`,
			});
		}

		// end_session confirmed: render the front-channel logout iframes before continuing to the
		// post_logout_redirect_uri / success page (oidcc-frontchannel-rp-initiated-logout), and change the OP
		// browser state so check_session_iframe answers "changed" (oidcc-session-management-rp-initiated-logout)
		if (ctx.method === "POST" && ctx.path === "/session/end/confirm" && ctx.status === 303) {
			const params = ctx.oidc?.params ?? {};
			ctx.cookies.set(OPBS_COOKIE, randomBytes(16).toString("base64url"), {
				httpOnly: false,
				sameSite: "lax",
				path: "/",
				overwrite: true,
				signed: false,
			});
			const pending = params.xsrf ? pendingFrontchannel.get(params.xsrf) : undefined;
			if (pending) {
				pendingFrontchannel.delete(params.xsrf);
				const frames = pending.frames.filter((f) => params.logout || f.clientId === pending.clientId).map((f) => f.url);
				if (frames.length) {
					const location = ctx.response.get("location");
					ctx.status = 200;
					ctx.type = "html";
					ctx.remove("location");
					ctx.body = frontchannelLogoutHtml(frames, location);
				}
			}
		}
	});

	const server: Server = await new Promise((resolve, reject) => {
		const s = tls
			? createHttpsServer(tls, provider.callback()).listen(port, host, () => resolve(s))
			: provider.listen(port, host, () => resolve(s));
		s.once("error", reject);
	});
	return {
		issuer,
		readyUrl: readyUrl(issuer),
		provider,
		server,
		close: () =>
			new Promise<void>((resolve) => {
				server.closeAllConnections();
				server.close(() => resolve());
			}),
	};
}

/** autoApprove mode: finish the login / consent prompt like the devInteractions forms would */
async function autoApproveInteraction(provider: Any, ctx: Any): Promise<void> {
	const { prompt, grantId, session, params } = await provider.interactionDetails(ctx.req, ctx.res);
	let result: Record<string, unknown>;
	if (prompt.name === "login") {
		result = { login: { accountId: "foo" } };
	} else {
		const grant = grantId
			? await provider.Grant.find(grantId)
			: new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
		const { details } = prompt;
		if (details.missingOIDCScope) {
			grant.addOIDCScope(details.missingOIDCScope.join(" "));
		}
		if (details.missingOIDCClaims) {
			grant.addOIDCClaims(details.missingOIDCClaims);
		}
		for (const [indicator, scope] of Object.entries(
			(details.missingResourceScopes ?? {}) as Record<string, string[]>,
		)) {
			grant.addResourceScope(indicator, scope.join(" "));
		}
		result = { consent: { grantId: await grant.save() } };
	}
	ctx.respond = false;
	await provider.interactionFinished(ctx.req, ctx.res, result, { mergeWithLastSubmission: prompt.name !== "login" });
}

function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const srv = createNetServer();
		srv.once("error", reject);
		srv.listen(0, "127.0.0.1", () => {
			const { port } = srv.address() as AddressInfo;
			srv.close(() => resolve(port));
		});
	});
}

async function dereferenceRequestUri(ctx: Any): Promise<void> {
	let params: Record<string, unknown>;
	if (ctx.method === "GET") {
		params = querystring.parse(ctx.querystring);
	} else {
		if (!ctx.is("application/x-www-form-urlencoded")) {
			return;
		}
		const chunks: Buffer[] = [];
		for await (const chunk of ctx.req) {
			chunks.push(chunk as Buffer);
		}
		const raw = Buffer.concat(chunks).toString("utf8");
		params = querystring.parse(raw);
		// oidc-provider falls back to an already parsed body when the stream was consumed
		ctx.request.body = raw;
	}
	const requestUri = params["request_uri"];
	if (typeof requestUri !== "string" || !/^https?:\/\//.test(requestUri) || params["request"] !== undefined) {
		return;
	}
	let requestObject: string;
	try {
		const res = await fetch(requestUri, {
			signal: AbortSignal.timeout(5000),
			headers: { accept: "application/oauth-authz-req+jwt, application/jwt" },
		});
		if (!res.ok) {
			return;
		}
		requestObject = (await res.text()).trim();
	} catch {
		return;
	}
	delete params["request_uri"];
	params["request"] = requestObject;
	const encoded = querystring.stringify(params as querystring.ParsedUrlQueryInput);
	if (ctx.method === "GET") {
		ctx.querystring = encoded;
	} else {
		ctx.request.body = encoded;
	}
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
	const running = await start();
	console.log(`oidc-provider listening, issuer ${running.issuer}, discovery ${running.readyUrl}`);
	console.log("ready");
	const shutdown = () => {
		void running.close().then(() => process.exit(0));
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
