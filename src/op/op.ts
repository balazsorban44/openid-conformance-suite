/**
 * What an OP test works with (the `op` fixture in tests/fixtures.ts provides it): the OP under test as the suite
 * discovered it, and the suite's own side of the conversation (its server, the scripted browser, the log).
 */
import type { Browser } from "../suite/browser.ts";
import type { TestConfig } from "../suite/config.ts";
import type { Jwks } from "../suite/jose.ts";
import type { EventLog } from "../suite/log.ts";
import type { TestServer } from "../suite/server.ts";
import type { ServerMetadata } from "./discovery.ts";

/** The variant parameters of the OIDCC OP test modules (upstream variant/*.java values) */
export interface OpVariant {
	server_metadata: "discovery" | "static";
	client_registration: "dynamic_client" | "static_client";
	client_auth_type:
		| "none"
		| "client_secret_basic"
		| "client_secret_post"
		| "client_secret_jwt"
		| "private_key_jwt"
		| "mtls";
	response_type: "code" | "id_token" | "id_token token" | "code id_token" | "code token" | "code id_token token";
	response_mode: "default" | "form_post";
	[parameter: string]: string;
}

export interface Op {
	/** The test module name (upstream testName), e.g. "oidcc-server" */
	testName: string;
	testId: string;
	/** The test configuration for this module (`override` applied) */
	config: TestConfig;
	variant: OpVariant;
	/** The OP's metadata (upstream env "server") */
	metadata: ServerMetadata;
	/** The OP's JWK set (upstream env "server_jwks") */
	jwks: Jwks;
	/** The suite's URL for this test (upstream base_url) */
	baseUrl: string;
	/** The suite's redirect_uri (upstream CreateRedirectUri) */
	redirectUri: string;
	server: TestServer;
	browser: Browser;
	log: EventLog;
}
