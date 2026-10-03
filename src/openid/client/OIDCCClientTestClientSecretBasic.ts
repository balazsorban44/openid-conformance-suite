import type { ModuleVariantMetadata, PublishTestModule } from "../../framework/index.ts";
import { OIDCCClientAuthType } from "../../variant/OIDCCClientAuthType.ts";
import { ResponseType } from "../../variant/ResponseType.ts";
import { AbstractOIDCCClientTest } from "./AbstractOIDCCClientTest.ts";

/**
 * applicable only when response type includes code
 */
export class OIDCCClientTestClientSecretBasic extends AbstractOIDCCClientTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-client-test-client-secret-basic",
		displayName: "OIDCC: Relying party test using client_secret_basic",
		summary:
			"The client MUST use client_secret_basic authentication method " +
			"regardless of selected client authentication type in test configuration." +
			"Corresponds to rp-token_endpoint-client_secret_basic in the old suite.",
		profile: "OIDCC",
		configurationFields: [],
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [{ parameter: ResponseType, values: ["id_token token", "id_token"] }],
	};

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "none")
	override setupClientAuthNone(): void {
		this.setupClientSecretBasic();
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "private_key_jwt")
	override setupPrivateKeyJwt(): void {
		this.setupClientSecretBasic();
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "client_secret_jwt")
	override setupClientSecretJWT(): void {
		this.setupClientSecretBasic();
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "client_secret_post")
	override setupClientSecretPost(): void {
		this.setupClientSecretBasic();
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "tls_client_auth")
	override setupTlsClientAuth(): void {
		this.setupClientSecretBasic();
	}

	// @VariantSetup(parameter = OIDCCClientAuthType.class, value = "self_signed_tls_client_auth")
	override setupSelfSignedTlsClientAuth(): void {
		this.setupClientSecretBasic();
	}

	protected override getEffectiveClientAuthTypeVariant(): OIDCCClientAuthType {
		return OIDCCClientAuthType.CLIENT_SECRET_BASIC;
	}
}
