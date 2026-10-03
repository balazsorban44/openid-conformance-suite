import { ExtractClientNameFromStoredConfig } from "../condition/client/ExtractClientNameFromStoredConfig.ts";
import { ExtractInitialAccessTokenFromStoredConfig } from "../condition/client/ExtractInitialAccessTokenFromStoredConfig.ts";
import { GetStaticClient2Configuration } from "../condition/client/GetStaticClient2Configuration.ts";
import { StoreOriginalClient2Configuration } from "../condition/client/StoreOriginalClient2Configuration.ts";
import { ClientAuthType } from "../variant/ClientAuthType.ts";
import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { type ModuleVariantMetadata } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export abstract class AbstractOIDCCMultipleClient extends AbstractOIDCCServerTest {
	static override variants: ModuleVariantMetadata = {
		configurationFields: [
			{ parameter: ClientAuthType, value: "client_secret_basic", configurationFields: ["client2.client_secret"] },
			{ parameter: ClientAuthType, value: "client_secret_post", configurationFields: ["client2.client_secret"] },
			{
				parameter: ClientAuthType,
				value: "client_secret_jwt",
				configurationFields: ["client2.client_secret", "client2.client_secret_jwt_alg"],
			},
			{ parameter: ClientAuthType, value: "private_key_jwt", configurationFields: ["client2.jwks"] },
			{ parameter: ClientAuthType, value: "mtls", configurationFields: ["mtls2.key", "mtls2.cert", "mtls2.ca"] },
			{ parameter: ClientRegistration, value: "static_client", configurationFields: ["client2.client_id"] },
			{
				parameter: ClientRegistration,
				value: "dynamic_client",
				configurationFields: ["client2.client_name", "client2.initial_access_token"],
			},
		],
	};

	protected override async configureClient(): Promise<void> {
		await super.configureClient();

		this.switchToSecondClient();
		switch (this.getVariant(ClientRegistration)) {
			case ClientRegistration.STATIC_CLIENT:
				await this.callAndStopOnFailure(GetStaticClient2Configuration);
				await this.configureStaticClient();
				break;
			case ClientRegistration.DYNAMIC_CLIENT:
				await this.callAndStopOnFailure(StoreOriginalClient2Configuration);
				await this.callAndStopOnFailure(ExtractClientNameFromStoredConfig);
				await this.callAndStopOnFailure(ExtractInitialAccessTokenFromStoredConfig);
				await this.configureDynamicClient();
				break;
		}

		await this.completeClientConfiguration();
		this.unmapClient();
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		if (!this.isSecondClient()) {
			this.switchToSecondClient();
			await this.performAuthorizationFlow();
		} else {
			await this.performSecondClientTests();
			await super.onPostAuthorizationFlowComplete();
		}
	}

	/**
	 * These are additional tests involving the second client,
	 * performed after the usual post-authorization flow.
	 */
	protected abstract performSecondClientTests(): Promise<void>;

	override async cleanup(): Promise<void> {
		this.unmapClient();
		await super.cleanup();
		this.switchToSecondClient();
		await this.unregisterClient();
	}

	protected override currentClientString(): string {
		if (this.isSecondClient()) {
			return "Second client: ";
		} else {
			return "";
		}
	}

	protected override isSecondClient(): boolean {
		return this.env.isKeyMapped("client");
	}

	protected switchToSecondClient(): void {
		this.env.mapKey("client", "client2");
		this.env.mapKey("client_jwks", "client_jwks2");
		this.env.mapKey("client_public_jwks", "client_public_jwks2");
		this.env.mapKey("mutual_tls_authentication", "mutual_tls_authentication2");
	}

	protected unmapClient(): void {
		this.env.unmapKey("client");
		this.env.unmapKey("client_jwks");
		this.env.unmapKey("client_public_jwks");
		this.env.unmapKey("mutual_tls_authentication");
	}
}
