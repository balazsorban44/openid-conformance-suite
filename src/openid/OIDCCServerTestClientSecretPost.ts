import { ClientRegistration } from "../variant/ClientRegistration.ts";
import { type JsonObject, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export class OIDCCServerTestClientSecretPost extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-server-client-secret-post",
		displayName: "OIDCC",
		summary: "Tests 'happy flow' using client_secret_post client authentication",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		configurationFields: [
			{
				parameter: ClientRegistration,
				value: "static_client",
				configurationFields: [
					// as the basic etc certification profiles run tests with different client authentication types, we need to
					// allow the user to provide multiple clients if using static clients (as many/most servers restrict each
					// clients to using only one authentication method)
					"client_secret_post.client_id",
					"client_secret_post.client_secret",
				],
			},
		],
	};

	protected override async configureClient(): Promise<void> {
		if (this.getVariant(ClientRegistration) === ClientRegistration.STATIC_CLIENT) {
			// copy the client_secret_post supporting client into the place the normal conditions expect to find it
			const config = this.env.getObject("config") as JsonObject;
			config["client"] = config["client_secret_post"] ?? null;
		}
		await super.configureClient();
	}
}
