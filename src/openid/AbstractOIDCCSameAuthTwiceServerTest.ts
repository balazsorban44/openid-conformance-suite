import { CheckIdTokenAuthTimeClaimsSameIfPresent } from "../condition/client/CheckIdTokenAuthTimeClaimsSameIfPresent.ts";
import { CheckIdTokenSubConsistentForSecondAuthorization } from "../condition/client/CheckIdTokenSubConsistentForSecondAuthorization.ts";
import { ConditionResult } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

/**
 * Calls the authorization endpoint twice, with subclass specified changes the second time, and expects the id_tokens
 * between the two calls to have the same auth_time (if present) and sub.
 */
export abstract class AbstractOIDCCSameAuthTwiceServerTest extends AbstractOIDCCServerTest {
	private firstTime = true;

	protected override currentClientString(): string {
		return this.firstTime ? "" : "Second authorization: ";
	}

	protected override async createAuthorizationRequest(): Promise<void> {
		if (this.firstTime) {
			// capture id_token from first authentication for later comparison (we don't care if it's from
			// the authorization endpoint or the token endpoint)
			this.env.mapKey("id_token", "first_id_token");
			await this.createFirstAuthorizationRequest();
		} else {
			this.env.unmapKey("id_token");
			await this.createSecondAuthorizationRequest();
		}
	}

	protected async createFirstAuthorizationRequest(): Promise<void> {
		await super.createAuthorizationRequest();
	}

	protected abstract createSecondAuthorizationRequest(): Promise<void>;

	protected override async onPostAuthorizationFlowComplete(): Promise<void> {
		if (this.firstTime) {
			this.firstTime = false;
			await this.validateFirstIdToken();
			// do the process again, but this time calling createSecondAuthorizationRequest()
			await this.performAuthorizationFlow();
		} else {
			await this.validateFirstAndSecondIdTokens();

			await this.fireTestFinished();
		}
	}

	protected async validateFirstIdToken(): Promise<void> {
		// no extra checks necessary beyond the generic ones in the superclass
	}

	protected async validateFirstAndSecondIdTokens(): Promise<void> {
		// these two checks are equivalent to same-authn, https://github.com/rohe/oidctest/blob/a306ff8ccd02da456192b595cf48ab5dcfd3d15a/src/oidctest/op/check.py#L1117

		// this check only works if the server actually returns auth_time; it might be better to explicitly request auth_time
		// in the first authorization but this matches what the original python tests did.
		// we could also time how long the second authorization endpoint call takes; it should really only take seconds as it
		// should just redirect straight back instantly.
		await this.callAndContinueOnFailure(CheckIdTokenAuthTimeClaimsSameIfPresent, ConditionResult.FAILURE, "OIDCC-2");
		await this.callAndContinueOnFailure(
			CheckIdTokenSubConsistentForSecondAuthorization,
			ConditionResult.FAILURE,
			"OIDCC-2",
		);
	}

	override async cleanup(): Promise<void> {
		this.firstTime = true; // to avoid any blocks created in cleanup being prefixed in currentClientString()
		await super.cleanup();
	}
}
