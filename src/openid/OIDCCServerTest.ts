import { ConditionResult, type PublishTestModule } from "../framework/index.ts";
import { EnsureIdTokenDoesNotContainName } from "../condition/client/EnsureIdTokenDoesNotContainName.ts";
import { EnsureIdTokenDoesNotContainNonRequestedClaims } from "../condition/client/EnsureIdTokenDoesNotContainNonRequestedClaims.ts";
import { EnsureMinimumAuthorizationCodeEntropy } from "../condition/client/EnsureMinimumAuthorizationCodeEntropy.ts";
import { EnsureMinimumAuthorizationCodeLength } from "../condition/client/EnsureMinimumAuthorizationCodeLength.ts";
import { ExtractAtHash } from "../condition/client/ExtractAtHash.ts";
import { ExtractCHash } from "../condition/client/ExtractCHash.ts";
import { ExtractExpiresInFromTokenEndpointResponse } from "../condition/client/ExtractExpiresInFromTokenEndpointResponse.ts";
import { ValidateAtHash } from "../condition/client/ValidateAtHash.ts";
import { ValidateCHash } from "../condition/client/ValidateCHash.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

export class OIDCCServerTest extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-server",
		displayName: "OIDCC",
		summary: "Tests primarily 'happy' flows",
		profile: "OIDCC",
	};

	protected override async performAuthorizationEndpointIdTokenValidation(): Promise<void> {
		await super.performAuthorizationEndpointIdTokenValidation();

		// OP-IDToken-at_hash
		await this.callAndContinueOnFailure(
			ExtractAtHash,
			this.responseType.includesToken() ? ConditionResult.FAILURE : ConditionResult.INFO,
			"OIDCC-3.3.2.11",
		);
		await this.skipIfMissing(
			["at_hash"],
			null,
			ConditionResult.INFO,
			ValidateAtHash,
			ConditionResult.FAILURE,
			"OIDCC-3.3.2.11",
		);

		// OP-IDToken_c_hash
		await this.callAndContinueOnFailure(
			ExtractCHash,
			this.responseType.includesCode() ? ConditionResult.FAILURE : ConditionResult.INFO,
			"OIDCC-3.3.2.11",
		);
		await this.skipIfMissing(
			["c_hash"],
			null,
			ConditionResult.INFO,
			ValidateCHash,
			ConditionResult.FAILURE,
			"OIDCC-3.3.2.11",
		);
	}

	protected override async additionalTokenEndpointResponseValidation(): Promise<void> {
		await super.additionalTokenEndpointResponseValidation();

		// issue warning if expires_in is missing (RFC6749 recommends it)
		await this.callAndContinueOnFailure(
			ExtractExpiresInFromTokenEndpointResponse,
			ConditionResult.WARNING,
			"RFC6749-5.1",
		);

		// at_hash and c_hash are optional in the token endpoint id_token, but if present must be correct
		await this.callAndContinueOnFailure(ExtractAtHash, ConditionResult.INFO, "OIDCC-3.3.2.11", "OIDCC-3.3.3.6");
		await this.skipIfMissing(
			["at_hash"],
			null,
			ConditionResult.INFO,
			ValidateAtHash,
			ConditionResult.FAILURE,
			"OIDCC-3.3.2.11",
		);

		await this.callAndContinueOnFailure(ExtractCHash, ConditionResult.INFO, "OIDCC-3.3.2.11", "OIDCC-3.3.3.6");
		await this.skipIfMissing(
			["c_hash"],
			null,
			ConditionResult.INFO,
			ValidateCHash,
			ConditionResult.FAILURE,
			"OIDCC-3.3.2.11",
		);
	}

	protected override async performIdTokenValidation(): Promise<void> {
		await super.performIdTokenValidation();

		// the python test did not check this as far as I know
		await this.callAndContinueOnFailure(
			EnsureIdTokenDoesNotContainName,
			ConditionResult.WARNING,
			"OIDCC-5.5",
			"OIDCC-5.5.1",
		);
	}

	protected override async performAuthorizationCodeValidation(): Promise<void> {
		await super.performAuthorizationCodeValidation();

		await this.callAndContinueOnFailure(
			EnsureMinimumAuthorizationCodeLength,
			ConditionResult.FAILURE,
			"RFC6749-10.10",
			"RFC6819-5.1.4.2-2",
		);

		await this.callAndContinueOnFailure(
			EnsureMinimumAuthorizationCodeEntropy,
			ConditionResult.FAILURE,
			"RFC6749-10.10",
			"RFC6819-5.1.4.2-2",
		);
	}

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		if (!this.isSecondClient()) {
			await this.callAndContinueOnFailure(EnsureIdTokenDoesNotContainNonRequestedClaims, ConditionResult.WARNING);
		}

		await super.onPostAuthorizationFlowComplete();
	}
}
