import { AddNonceToAuthorizationEndpointRequest } from "../condition/client/AddNonceToAuthorizationEndpointRequest.ts";
import { ResponseType } from "../variant/ResponseType.ts";
import { type ConditionSequence, type ModuleVariantMetadata, type PublishTestModule } from "../framework/index.ts";
import { AbstractOIDCCServerTest } from "./AbstractOIDCCServerTest.ts";

// Equivalent of https://www.heenan.me.uk/~joseph/oidcc_test_desc-phase1.html#OP_nonce_NoReq_code
export class OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow extends AbstractOIDCCServerTest {
	static override readonly meta: PublishTestModule = {
		testName: "oidcc-ensure-request-without-nonce-succeeds-for-code-flow",
		displayName: "OIDCC: ensure request without nonce succeeds (non-implicit flows)",
		summary:
			"This test should end with the authorization server issuing an authorization code, even though a nonce was not supplied. nonce is required for all flows that return an id_token from the authorization endpoint, see https://bitbucket.org/openid/connect/issues/972/nonce-requirement-in-hybrid-auth-request / https://bitbucket.org/openid/connect/issues/1052/make-clear-that-nonce-is-always-required and the latest OpenID Connect errata draft, https://openid.net/specs/openid-connect-core-1_0-27.html#NonceNotes",
		profile: "OIDCC",
	};

	static override variants: ModuleVariantMetadata = {
		notApplicable: [
			{ parameter: ResponseType, values: ["id_token", "id_token token", "code id_token", "code id_token token"] },
		],
	};

	protected override createAuthorizationRequestSequence(): ConditionSequence {
		return super
			.createAuthorizationRequestSequence()
			.skip(AddNonceToAuthorizationEndpointRequest, "NOT adding nonce to request object");
	}

	protected override async performPostAuthorizationFlow(): Promise<void> {
		await this.onPostAuthorizationFlowComplete();
	}
}
