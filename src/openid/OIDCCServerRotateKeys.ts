import { CheckServerKeysIsValid } from "../condition/client/CheckServerKeysIsValid.ts";
import { FetchServerKeys } from "../condition/client/FetchServerKeys.ts";
import { GetDynamicServerConfiguration } from "../condition/client/GetDynamicServerConfiguration.ts";
import { GetStaticServerConfiguration } from "../condition/client/GetStaticServerConfiguration.ts";
import { TellUserToRotateOpKeys } from "../condition/client/TellUserToRotateOpKeys.ts";
import { ValidateJwksSequence } from "../sequence/ValidateJwksSequence.ts";
import { VerifyNewJwksHasNewSigningKey } from "../condition/client/VerifyNewJwksHasNewSigningKey.ts";
import { VerifyNewJwksStillHasOldSigningKey } from "../condition/client/VerifyNewJwksStillHasOldSigningKey.ts";
import { CheckDistinctKeyIdValueInServerJWKs } from "../condition/common/CheckDistinctKeyIdValueInServerJWKs.ts";
import { CheckForKeyIdInServerJWKs } from "../condition/common/CheckForKeyIdInServerJWKs.ts";
import { CheckServerConfiguration } from "../condition/common/CheckServerConfiguration.ts";
import { ServerMetadata } from "../variant/ServerMetadata.ts";
import {
	AbstractTestModule,
	ConditionResult,
	Status,
	type JsonObject,
	type ModuleVariantMetadata,
	type PublishTestModule,
} from "../framework/index.ts";

export class OIDCCServerRotateKeys extends AbstractTestModule {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-server-rotate-keys",
		displayName: "OIDCC",
		summary:
			"Test that the authorization server is able to rotate signing keys held in it's jwks_uri, by comparing the contents of the jwks_uri before and after rotation; it must have a new key and should still contain the old key as well. Before pressing the 'Start' button, please trigger a key rotation in your OP. If you are not able to cause the server to rotate the keys while running the test, then you will have to self-assert that your deployment can do OP signing key rotation as part of your certification application, see the section about 'Attestation Statement' on https://openid.net/certification/submission/",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		parameters: [ServerMetadata],
		configurationFields: [
			{ parameter: ServerMetadata, value: "static", configurationFields: ["server.issuer", "server.token_endpoint"] },
			{ parameter: ServerMetadata, value: "discovery", configurationFields: ["server.discoveryUrl"] },
		],
	};

	override autoStart(): boolean {
		// we want the user to manually start the test once they've rotated the keys
		return false;
	}

	// Java: final
	override async configure(
		config: JsonObject,
		baseUrl: string,
		_externalUrlOverride: string,
		baseMtlsUrl: string,
	): Promise<void> {
		this.env.putString("base_url", baseUrl);
		this.env.putString("base_mtls_url", baseMtlsUrl);
		this.env.putObject("config", config);

		switch (this.getVariant(ServerMetadata)) {
			case ServerMetadata.DISCOVERY:
				await this.callAndStopOnFailure(GetDynamicServerConfiguration);
				break;
			case ServerMetadata.STATIC:
				await this.callAndStopOnFailure(GetStaticServerConfiguration);
				break;
		}

		// make sure the server configuration passes some basic sanity checks
		await this.callAndStopOnFailure(CheckServerConfiguration);

		this.eventLog.startBlock("Fetch & validate current server keys");
		this.env.mapKey("server_jwks", "original_jwks");
		await this.fetchAndValidateJwks();
		this.eventLog.endBlock();

		await this.callAndStopOnFailure(TellUserToRotateOpKeys);

		await this.setStatus(Status.CONFIGURED);
		this.fireSetupDone();
	}

	private async fetchAndValidateJwks(): Promise<void> {
		await this.callAndStopOnFailure(FetchServerKeys);
		await this.callAndContinueOnFailure(CheckServerKeysIsValid, ConditionResult.FAILURE);
		await this.call(new ValidateJwksSequence("server_jwks", null, "server JWKS", "RFC7517-1.1"));
		await this.callAndContinueOnFailure(CheckForKeyIdInServerJWKs, ConditionResult.FAILURE, "OIDCC-10.1");
		await this.callAndContinueOnFailure(CheckDistinctKeyIdValueInServerJWKs, ConditionResult.FAILURE, "RFC7517-4.5");
	}

	override async start(): Promise<void> {
		await this.setStatus(Status.RUNNING);

		this.eventLog.startBlock("Fetch & validate new server keys");
		this.env.mapKey("server_jwks", "new_jwks");
		await this.fetchAndValidateJwks();
		this.eventLog.endBlock();

		// note that we don't actually check if the server now uses the new key to sign id_tokens (same as python)
		await this.callAndContinueOnFailure(VerifyNewJwksHasNewSigningKey, ConditionResult.FAILURE, "OIDCC-10.1.1");
		// the python suite did not check this
		await this.callAndContinueOnFailure(VerifyNewJwksStillHasOldSigningKey, ConditionResult.WARNING, "OIDCC-10.1.1");

		await this.fireTestFinished();
	}
}
