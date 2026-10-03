/**
 * OpenID Connect Third Party-Initiated Login: OP tests (upstream openid/OIDCC3rdPartyInitLoginTestPlan.java, the
 * 'Third Party-Initiated Login OP' certification profile).
 *
 * The plan fixes server_metadata=discovery, client_registration=dynamic_client, client_auth_type=client_secret_basic
 * and response_mode=default; the user selects response_type. The OP may require an https initiate_login_uri (the
 * bundled oidc-provider does): run with CONFORMANCE_TLS=1 (`openid-conformance ci` does).
 *
 *   CONFORMANCE_PROJECT=op-3rdparty-init-login CONFORMANCE_TLS=1 pnpm test tests/op/3rdparty-init-login.spec.ts
 */
import * as discovery from "../../src/op/discovery.ts";
import { ensureContentTypeJson, ensureHttpStatusCodeIs400 } from "../../src/op/endpoint.ts";
import * as initiateLogin from "../../src/op/initiate-login.ts";
import { checkDistinctKeyIdValueInClientJWKs } from "../../src/op/jwks.ts";
import * as registration from "../../src/op/registration.ts";
import { block, skipped, soft } from "../../src/suite/conditions.ts";
import { test } from "../fixtures.ts";

const PLAN = "oidcc-3rdparty-init-login-certification-test-plan";

test.describe(PLAN, () => {
	test.use({
		plan: {
			name: PLAN,
			variant: {
				server_metadata: "discovery",
				client_registration: "dynamic_client",
				client_auth_type: "client_secret_basic",
				response_mode: "default",
			},
		},
	});

	// upstream: openid/OIDCC3rdPartyInitLogin.java (OP-3rd_party-init-login)
	test("oidcc-3rd_party-init-login: the OP keeps the registered initiate_login_uri in the registration and the client configuration", async ({
		op,
		configureClient,
	}) => {
		let initiateLoginUri = "";
		const client = await configureClient((request) => {
			initiateLoginUri = initiateLogin.createInitiateLoginUri(op.baseUrl, "OIDCC-4", "OIDCR-2");
			initiateLogin.addInitiateLoginUriToDynamicRegistrationRequest(request, initiateLoginUri, "OIDCC-4", "OIDCR-2");
		});
		// UPSTREAM: configured by AbstractOIDCCServerTest, though this module calls no protected resource
		discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		soft(() =>
			initiateLogin.validateInitiateLoginUriInRegistrationResponse(client.client, initiateLoginUri, "OIDCR-3.2"),
		);

		// the python suite called the client configuration endpoint; not obviously mandatory to implement for this
		// profile, but kept
		await block("Call client configuration endpoint", async () => {
			const response = await registration.callClientConfigurationEndpoint(client.client, "OIDCD-4.2");
			soft(() => registration.checkRegistrationClientEndpointContentTypeHttpStatus200(response, "OIDCD-4.3"));
			soft(() => registration.checkRegistrationClientEndpointContentType(response, "OIDCD-4.3"));
			soft(() =>
				initiateLogin.validateInitiateLoginUriInConfigurationResponse(response, initiateLoginUri, "OIDCD-4.3"),
			);
		});
	});

	// upstream: openid/OIDCC3rdPartyInitLoginNonHttps.java (OP-3rd_party-init-login-nohttps)
	test("oidcc-3rd_party-init-login-nohttps: the OP rejects the registration of a non-https initiate_login_uri with invalid_client_metadata", async ({
		op,
	}) => {
		// the OIDCC registration request (upstream OIDCCCreateDynamicClientRegistrationRequest) with an http
		// initiate_login_uri
		const original = registration.storeOriginalClientConfiguration(op.config);
		const clientName = registration.extractClientNameFromStoredConfig(original);
		const initialAccessToken = registration.extractInitialAccessTokenFromStoredConfig(original);
		const keys = registration.generateRS256ClientJWKs();
		soft(() => checkDistinctKeyIdValueInClientJWKs(keys.jwks, "RFC7517-4.5"));
		const request = registration.createDynamicRegistrationRequest(op.testId, {
			clientName,
			responseType: op.variant.response_type,
			clientAuthType: op.variant.client_auth_type,
			redirectUri: op.redirectUri,
			publicJwks: keys.publicJwks,
		});
		const initiateLoginUri = initiateLogin.createInitiateLoginUri(op.baseUrl, "OIDCC-4", "OIDCR-2");
		initiateLogin.addInitiateLoginUriAsNonHttpsToDynamicRegistrationRequest(
			request,
			initiateLoginUri,
			"OIDCC-4",
			"OIDCR-2",
		);

		const response = await registration.callDynamicRegistrationEndpoint(
			op.metadata,
			request,
			initialAccessToken,
			"RFC6749-3.1.2",
		);
		soft(() => ensureContentTypeJson(response));
		soft(() => ensureHttpStatusCodeIs400(response));
		soft(() => registration.checkErrorFromDynamicRegistrationEndpointIsInvalidClientMetadata(response, "OIDCR-3.3"));
		// UPSTREAM: configured by AbstractOIDCCServerTest, though this module calls no protected resource
		discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);

		// upstream's cleanup: no client was registered
		await block("Unregister dynamically registered client", () =>
			skipped("UnregisterDynamicallyRegisteredClient", { object: "client" }),
		);
	});
});
