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
 *   OIDC_PROVIDER_TLS_CERT / _KEY     PEM file paths: serve https (the suite requires https for registration_client_uri,
 *                                     initiate_login_uri, sector_identifier_uri ...); the default ISSUER is then https
 *   OIDC_PROVIDER_AUTO_APPROVE=1      self-test mode for the RP target: no login/consent/logout user interaction
 *   OIDC_PROVIDER_PROFILE=fapi2       FAPI 2.0 Security Profile mode (the fapi2-* plans): oidc-provider's FAPI 2.0
 *                                     profile, PAR required, DPoP with server nonces, JARM, signed request objects,
 *                                     PKCE S256, private_key_jwt clients (clients-fapi2.json), x-fapi-interaction-id
 *                                     on userinfo responses. Without it the target behaves as for the OIDCC plans.
 *   DEBUG_OIDC_PROVIDER=1             log every request and provider error
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { fileURLToPath } from "node:url";
import * as querystring from "node:querystring";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from "jose";
import Provider, { errors } from "oidc-provider";
import { defaults } from "oidc-provider/lib/helpers/defaults.js";
import * as jwa from "oidc-provider/lib/consts/jwa.js";

// oidc-provider has no type declarations, its objects are handled untyped
// oxlint-disable-next-line typescript/no-explicit-any
type Any = any;

const env = process.env;
const PORT = Number(env["PORT"] ?? 3000);
const DEBUG = env["DEBUG_OIDC_PROVIDER"] === "1";
/**
 * Self-test mode for the RP target (OIDC_PROVIDER_AUTO_APPROVE=1): login (as "foo"), consent and the logout
 * confirmation complete without user interaction. Never used for the OP plans.
 */
const AUTO_APPROVE = env["OIDC_PROVIDER_AUTO_APPROVE"] === "1";
/**
 * FAPI 2.0 mode (OIDC_PROVIDER_PROFILE=fapi2): what the fapi2-security-profile-final / fapi2-message-signing-final
 * plans need from the OP under test. Everything else stays as for the OIDCC plans.
 */
const FAPI2 = env["OIDC_PROVIDER_PROFILE"] === "fapi2";
const TLS =
	env["OIDC_PROVIDER_TLS_CERT"] && env["OIDC_PROVIDER_TLS_KEY"]
		? {
				cert: readFileSync(env["OIDC_PROVIDER_TLS_CERT"], "utf8"),
				key: readFileSync(env["OIDC_PROVIDER_TLS_KEY"], "utf8"),
			}
		: null;
const ISSUER = (env["ISSUER"] ?? `${TLS ? "https" : "http"}://localhost:${PORT}`).replace(/\/$/, "");

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

/**
 * static clients may use any suite redirect URI on the loopback host (the suite port is dynamic); the FAPI plans'
 * second client registers the redirect URI with the query suffix of upstream's instructions
 * (AddRedirectUriQuerySuffix), which is accepted as such in FAPI 2.0 mode
 */
const suiteUri = (endpoint: string, suffix = "") =>
	new RegExp(String.raw`^https?://(localhost|127\.0\.0\.1)(:\d+)?/test/(a/[^/?#]+|[^/?#]+)/${endpoint}${suffix}$`);
const STATIC_CLIENT_URIS = {
	redirectUriAllowed: suiteUri("callback", FAPI2 ? String.raw`(\?dummy1=lorem&dummy2=ipsum)?` : ""),
	postLogoutRedirectUriAllowed: suiteUri("post_logout_redirect"),
};

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
		const jwk = { ...(await exportJWK(privateKey)), use };
		keys.push({ ...jwk, kid: await calculateJwkThumbprint(jwk) });
	}
	return { keys };
}

const sha256url = (input: string) => createHash("sha256").update(input).digest("base64url");

const htmlSafe = (value: unknown) =>
	String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");

const setOpbs = (ctx: Any, value: string) =>
	ctx.cookies.set(OPBS_COOKIE, value, { httpOnly: false, sameSite: "lax", path: "/", overwrite: true, signed: false });

/** check_session_iframe page (OIDC Session Management 1.0 section 3.3), recomputes session_state from the cookie */
const CHECK_SESSION_IFRAME_HTML = `<!DOCTYPE html>
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

export async function start(): Promise<{ issuer: string; close(): Promise<void> }> {
	const staticClients: Record<string, unknown>[] = JSON.parse(
		env["OIDC_PROVIDER_CLIENTS"] ||
			readFileSync(
				env["OIDC_PROVIDER_CLIENTS_FILE"] ?? new URL(FAPI2 ? "clients-fapi2.json" : "clients.json", import.meta.url),
				"utf8",
			),
	);
	const staticClientIds = new Set(staticClients.map((c) => String(c["client_id"])));

	// ML-DSA is filtered out like upstream's CI (conformance-suite#1598); everything else oidc-provider implements is
	// enabled so the suite can register clients with any id_token/userinfo/request object alg it wants to test
	// (DPoP and attestation algs keep their defaults, those features are off)
	const enabledJWA = Object.fromEntries(
		Object.keys(defaults.enabledJWA)
			.filter((key) => !/^(dPoP|attest)/.test(key))
			.map((key) => [
				key,
				(jwa as unknown as Record<string, string[]>)[key].filter((alg) => !alg.startsWith("ML-DSA")),
			]),
	);
	if (FAPI2) {
		// FAPI 2.0 5.4: PS256 / ES256 / EdDSA; the suite's DPoP key follows the client's dpop_signing_alg when the
		// OP lists it, else the first algorithm listed (GenerateDpopKey)
		enabledJWA["dPoPSigningAlgValues"] = ["ES256", "PS256", "Ed25519", "EdDSA"];
	}

	// front-channel logout iframes pending per logout confirmation (keyed by the end_session xsrf secret)
	const pendingFrontchannel = new Map<string, { clientId?: string; frames: { clientId: string; url: string }[] }>();

	const provider = new Provider(ISSUER, {
		// OIDC Core 3.1.2.1: the authorization endpoint MUST support POST (oidcc-ensure-post-request-succeeds);
		// oidc-provider then requires SameSite=None on its long-lived (session) cookies
		enableHttpPostMethods: true,
		clients: staticClients,
		jwks: env["OIDC_PROVIDER_JWKS"] ? JSON.parse(env["OIDC_PROVIDER_JWKS"]) : await generateJwks(),
		cookies: {
			keys: [randomBytes(32).toString("base64url")],
			long: { sameSite: "none", signed: true },
			short: { sameSite: "lax", signed: true },
		},
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
			// oidcc-request-*, oidcc-unsigned-request-object-*, oidcc-ensure-request-object-*: request parameter;
			// fapi2-message-signing-final-* (signed_non_repudiation): the request object pushed to the PAR endpoint
			requestObjects: { enabled: true, requireSignedRequestObject: false },
			// FAPI 2.0 mode: oidc-provider's FAPI 2.0 profile (PKCE S256 required, request objects need exp/nbf/aud,
			// no access tokens in the query), PAR required, DPoP with server-provided nonces (RFC9449-8.2: the suite's
			// nonce retry at the PAR, token and resource endpoints is exercised on every call), JARM
			...(FAPI2
				? {
						fapi: { enabled: true, profile: "2.0" },
						dPoP: { enabled: true, nonceSecret: randomBytes(32), requireNonce: () => true },
						pushedAuthorizationRequests: { enabled: true, requirePushedAuthorizationRequests: true },
						jwtResponseModes: { enabled: true },
					}
				: {}),
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
						if (uri) {
							const url = new URL(uri);
							url.searchParams.set("iss", ISSUER);
							url.searchParams.set("sid", session.sidFor(clientId));
							frames.push({ clientId, url: url.href });
						}
					}
					if (frames.length) {
						pendingFrontchannel.set(session.state.secret, { clientId: session.state.clientId, frames });
					}
					await defaults.features.rpInitiatedLogout.logoutSource(ctx, form);
					if (AUTO_APPROVE) {
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
		// PKCE is optional (the OIDC plans only send it in some modules); FAPI 2.0 requires S256
		pkce: { required: () => FAPI2 },
		// oidcc-ensure-redirect-uri-in-authorization-request: redirect_uri is REQUIRED in OIDC, even with one registered
		allowOmittingSingleRegisteredRedirectUri: false,
		// oidcc-refresh-token / oidcc-refresh-token-rp-key-rotation: refresh tokens for offline_access (same rule as
		// upstream's certification config)
		async issueRefreshToken(_ctx: Any, client: Any, code: Any) {
			return (
				client.grantTypeAllowed("refresh_token") &&
				(code.scopes.has("offline_access") || (client.applicationType === "web" && client.clientAuthMethod === "none"))
			);
		},
		async findAccount(_ctx: Any, sub: string) {
			return { accountId: sub, claims: async () => ({ sub, ...structuredClone(ACCOUNT_CLAIMS) }) };
		},
		ttl: { RegistrationAccessToken: 24 * 60 * 60 },
		// outgoing requests (backchannel_logout_uri, jwks_uri, sector_identifier_uri, request_uri) go to the suite on
		// localhost; oidc-provider's default dispatcher refuses loopback/private addresses, so use plain fetch like
		// upstream's certification config does for oidcc-dynamic-* and oidcc-backchannel-rp-initiated-logout
		fetch(url: URL | string, { dispatcher: _, ...options }: RequestInit & { dispatcher?: unknown }) {
			return globalThis.fetch(url, options);
		},
	});

	// the suite runs on http://localhost: allow implicit/hybrid clients to register http and localhost redirect_uris
	// (oidcc-implicit-*, oidcc-hybrid-* plans and every logout plan with response_type including id_token)
	const { invalidate } = provider.Client.Schema.prototype;
	provider.Client.Schema.prototype.invalidate = function (message: string, code?: string) {
		if (code !== "implicit-force-https" && code !== "implicit-forbid-localhost") {
			return invalidate.call(this, message, code);
		}
	};

	// static_client variants: the suite's redirect_uri contains its dynamic port, accept any suite callback URL on
	// the loopback host for the static clients (still exact-path, so oidcc-ensure-registered-redirect-uri fails)
	for (const [method, pattern] of Object.entries(STATIC_CLIENT_URIS)) {
		const original = provider.Client.prototype[method];
		provider.Client.prototype[method] = function (value: string) {
			return (staticClientIds.has(this.clientId) && pattern.test(value)) || original.call(this, value);
		};
	}

	// oidcc-frontchannel-rp-initiated-logout (CheckIdTokenSidMatchesFrontChannelLogoutRequest) and the back-channel
	// logout plan compare the sid of the ID Token with the logout request: always include sid in ID Tokens
	provider.Client.prototype.includeSid = () => true;

	// oidcc-ensure-request-with-acr-values-succeeds etc.: like upstream, assert a static acr/amr on every login
	const { interactionFinished } = provider;
	provider.interactionFinished = (...args: Any[]) => {
		if (args[2].login) {
			Object.assign(args[2].login, { acr: ACR, amr: ["pwd"] });
		}
		return interactionFinished.call(provider, ...args);
	};

	// OIDC Session Management 1.0: add session_state to every successful authorization response and keep the OP
	// browser state cookie in sync (oidcc-session-management-certification-test-plan)
	provider.on("authorization.success", (ctx: Any, out: Record<string, unknown>) => {
		const { session, client } = ctx.oidc;
		const redirectUri = ctx.oidc.params?.redirect_uri;
		if (!session?.accountId || !client || !redirectUri || !URL.canParse(redirectUri)) {
			return;
		}
		const opbs = sha256url(`${session.uid}:${session.loginTs ?? ""}`);
		setOpbs(ctx, opbs);
		// section 3: session_state = hash(client_id origin opbs salt) + "." + salt
		const salt = randomBytes(8).toString("base64url");
		out["session_state"] = `${sha256url(`${client.clientId} ${new URL(redirectUri).origin} ${opbs} ${salt}`)}.${salt}`;
	});

	if (DEBUG) {
		provider.on("server_error", (_ctx: Any, err: Error) => console.error("server_error", err));
		for (const event of ["authorization.error", "grant.error", "backchannel.error"]) {
			provider.on(event, (_ctx: Any, err: Error) => console.error(event, err.message));
		}
	}

	provider.use(async (ctx: Any, next: () => Promise<void>) => {
		if (DEBUG) {
			console.log(ctx.method, ctx.url);
		}

		if (AUTO_APPROVE && ctx.method === "GET" && ctx.path.startsWith("/interaction/")) {
			return autoApproveInteraction(provider, ctx);
		}

		// check_session_iframe (oidcc-session-management-*)
		if (ctx.method === "GET" && ctx.path === "/session/check") {
			ctx.type = "html";
			ctx.set("cache-control", "no-store");
			ctx.body = CHECK_SESSION_IFRAME_HTML;
			return;
		}

		// request_uri by reference (oidcc-request-uri-unsigned, oidcc-request-uri-signed-*): oidc-provider v9 only
		// supports PAR request_uris, so dereference http(s) request_uris here and pass the object on as `request`
		if (ctx.path === "/auth" && (ctx.method === "GET" || ctx.method === "POST")) {
			await dereferenceRequestUri(ctx);
		}

		await next();

		// FAPI 2.0 mode: the resource server echoes (or creates) the x-fapi-interaction-id of a userinfo request
		// (FAPI 2.0 Implementation Advice 2.1.1, CheckForFAPIInteractionIdInResourceResponse)
		if (FAPI2 && ctx.path === "/me") {
			const interactionId = ctx.get("x-fapi-interaction-id");
			ctx.set("x-fapi-interaction-id", interactionId || randomUUID());
		}

		// discovery additions for the features implemented in this file
		if (ctx.path === "/.well-known/openid-configuration" && ctx.status === 200 && ctx.body) {
			Object.assign(ctx.body, {
				request_uri_parameter_supported: true,
				require_request_uri_registration: false,
				frontchannel_logout_supported: true,
				frontchannel_logout_session_supported: true,
				check_session_iframe: `${ISSUER}/session/check`,
			});
		}

		// end_session confirmed: render the front-channel logout iframes before continuing to the
		// post_logout_redirect_uri / success page (oidcc-frontchannel-rp-initiated-logout), and change the OP
		// browser state so check_session_iframe answers "changed" (oidcc-session-management-rp-initiated-logout)
		if (ctx.method === "POST" && ctx.path === "/session/end/confirm" && ctx.status === 303) {
			const params = ctx.oidc?.params ?? {};
			setOpbs(ctx, randomBytes(16).toString("base64url"));
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
		const s = TLS ? createHttpsServer(TLS, provider.callback()) : createServer(provider.callback());
		// all interfaces (dual-stack): `localhost` resolves to ::1 on some hosts and 127.0.0.1 on others
		s.once("error", reject).listen(PORT, () => resolve(s));
	});
	return {
		issuer: ISSUER,
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
	try {
		const res = await fetch(requestUri, {
			signal: AbortSignal.timeout(5000),
			headers: { accept: "application/oauth-authz-req+jwt, application/jwt" },
		});
		if (!res.ok) {
			return;
		}
		params["request"] = (await res.text()).trim();
	} catch {
		return;
	}
	delete params["request_uri"];
	const encoded = querystring.stringify(params as querystring.ParsedUrlQueryInput);
	if (ctx.method === "GET") {
		ctx.querystring = encoded;
	} else {
		ctx.request.body = encoded;
	}
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
	const running = await start();
	console.log(
		`oidc-provider listening, issuer ${running.issuer}, discovery ${running.issuer}/.well-known/openid-configuration`,
	);
	console.log("ready");
	const shutdown = () => void running.close().then(() => process.exit(0));
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
