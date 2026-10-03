import {
	AbstractConditionSequence,
	ConditionCallBuilder,
	ConditionResult,
	type Condition,
	type ConditionClass,
	type ConditionSequenceClass,
	type TestExecutionUnit,
} from "../../framework/index.ts";
import { AddScopeToTokenEndpointRequest } from "../../condition/client/AddScopeToTokenEndpointRequest.ts";
import { CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse } from "../../condition/client/CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse.ts";
import { CallTokenEndpointAndReturnFullResponse } from "../../condition/client/CallTokenEndpointAndReturnFullResponse.ts";
import { CheckIfTokenEndpointResponseError } from "../../condition/client/CheckIfTokenEndpointResponseError.ts";
import { CheckTokenEndpointCacheHeaders } from "../../condition/client/CheckTokenEndpointCacheHeaders.ts";
import { CheckTokenEndpointHttpStatus200 } from "../../condition/client/CheckTokenEndpointHttpStatus200.ts";
import { CheckTokenEndpointReturnedJsonContentType } from "../../condition/client/CheckTokenEndpointReturnedJsonContentType.ts";
import { CheckTokenTypeIsBearer } from "../../condition/client/CheckTokenTypeIsBearer.ts";
import { CheckTokenTypeIsDpop } from "../../condition/client/CheckTokenTypeIsDpop.ts";
import { CompareIdTokenClaims } from "../../condition/client/CompareIdTokenClaims.ts";
import { CreateRefreshTokenRequest } from "../../condition/client/CreateRefreshTokenRequest.ts";
import { EnsureAccessTokenContainsAllowedCharactersOnly } from "../../condition/client/EnsureAccessTokenContainsAllowedCharactersOnly.ts";
import { EnsureAccessTokenValuesAreDifferent } from "../../condition/client/EnsureAccessTokenValuesAreDifferent.ts";
import { EnsureMinimumAccessTokenEntropy } from "../../condition/client/EnsureMinimumAccessTokenEntropy.ts";
import { EnsureMinimumRefreshTokenEntropy } from "../../condition/client/EnsureMinimumRefreshTokenEntropy.ts";
import { EnsureMinimumRefreshTokenLength } from "../../condition/client/EnsureMinimumRefreshTokenLength.ts";
import { ExtractAccessTokenFromTokenResponse } from "../../condition/client/ExtractAccessTokenFromTokenResponse.ts";
import { ExtractExpiresInFromTokenEndpointResponse } from "../../condition/client/ExtractExpiresInFromTokenEndpointResponse.ts";
import { ExtractIdTokenFromTokenResponse } from "../../condition/client/ExtractIdTokenFromTokenResponse.ts";
import { ExtractRefreshTokenFromTokenResponse } from "../../condition/client/ExtractRefreshTokenFromTokenResponse.ts";
import { GenerateDpopKey } from "../../condition/client/GenerateDpopKey.ts";
import { ValidateExpiresIn } from "../../condition/client/ValidateExpiresIn.ts";
import { ValidateIdTokenFromTokenResponseEncryption } from "../../condition/client/ValidateIdTokenFromTokenResponseEncryption.ts";
import { WaitForOneSecond } from "../../condition/client/WaitForOneSecond.ts";
import { CreateDpopProofSteps } from "./CreateDpopProofSteps.ts";

// Java: AbstractConditionSequence.actionToConditionClass (a protected static there; the framework port keeps it
// module-private, so it is repeated here)
function actionToConditionClass(action: TestExecutionUnit): ConditionClass | null {
	if (action instanceof ConditionCallBuilder) {
		return action.getConditionClass();
	}
	const c = action as unknown as Condition;
	if (typeof c.execute === "function" && typeof c.setProperties === "function") {
		return action.constructor as ConditionClass;
	}
	return null;
}

/**
 * Use the refresh token to fetch a new access token and (possibly) ID token, and compare the two.
 * The original access token and ID token should be stored as "first_access_token" and
 * "first_id_token" respectively, and there should be an environment mapping from "access_token" to
 * "second_access_token", and from "id_token" to "second_id_token".
 * See FAPIRWID2RefreshToken for an example of how to do this.
 */
export class RefreshTokenRequestSteps extends AbstractConditionSequence {
	private secondClient: boolean;
	private isDpop: boolean;
	private testTitle: string | null;
	private currentClient: string;
	private addClientAuthenticationToTokenEndpointRequest: ConditionSequenceClass | null;

	/**
	 * Java overloads: (secondClient, addClientAuthentication), (secondClient, addClientAuthentication, isDpop),
	 * (secondClient, addClientAuthentication, isDpop, testTitle)
	 */
	constructor(
		secondClient: boolean,
		addClientAuthenticationToTokenEndpointRequest: ConditionSequenceClass | null,
		isDpop = false,
		testTitle: string | null = null,
	) {
		super();
		this.secondClient = secondClient;
		this.isDpop = isDpop;
		this.testTitle = testTitle;
		this.currentClient = secondClient ? "Second client: " : "";
		this.addClientAuthenticationToTokenEndpointRequest = addClientAuthenticationToTokenEndpointRequest;
	}

	override evaluate(): void {
		if (this.testTitle == null) {
			this.testTitle = "Refresh Token Request";
		}
		this.call(this.exec().startBlock(this.currentClient + this.testTitle));

		this.callAndStopOnFailure(CreateRefreshTokenRequest);
		if (!this.secondClient) {
			this.callAndStopOnFailure(AddScopeToTokenEndpointRequest, "RFC6749-6");
		}

		if (this.addClientAuthenticationToTokenEndpointRequest != null) {
			this.call(
				this.exec()
					.mapKey("request_form_parameters", "token_endpoint_request_form_parameters")
					.mapKey("request_headers", "token_endpoint_request_headers"),
			);
			this.call(this.sequence(this.addClientAuthenticationToTokenEndpointRequest));
			this.call(this.exec().unmapKey("request_form_parameters").unmapKey("request_headers"));
		}

		//wait 1 second to make sure that iat values will be different
		this.callAndStopOnFailure(WaitForOneSecond);

		if (this.isDpop) {
			// we generate a new key here, to check the server handles that correctly - so this isn't suitable for
			// public clients where the refresh token is bound to the dpop key
			this.callAndStopOnFailure(GenerateDpopKey);
			this.call(CreateDpopProofSteps.createTokenEndpointDpopSteps());
			this.callAndStopOnFailure(CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse);

			// retry request if token_endpoint_dpop_nonce_error is found
			this.call(this.exec().startBlock("Token endpoint DPoP nonce retry"));

			// repeat conditions in CreateDpopProofSteps.createTokenEndpointDpopSteps() only if token_endpoint_dpop_nonce_error is found
			const seq = CreateDpopProofSteps.createTokenEndpointDpopSteps();
			seq.evaluate();
			const condList = seq.getTestExecutionUnits().map(actionToConditionClass) as ConditionClass[];
			for (const cond of condList) {
				this.call(
					this.condition(cond).skipIfStringsMissing("token_endpoint_dpop_nonce_error").onSkip(ConditionResult.INFO),
				);
			}

			this.call(
				this.condition(CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse)
					.skipIfStringsMissing("token_endpoint_dpop_nonce_error")
					.onSkip(ConditionResult.INFO),
			);
			this.call(this.exec().endBlock());
		} else {
			this.callAndStopOnFailure(CallTokenEndpointAndReturnFullResponse);
		}

		this.callAndContinueOnFailure(CheckTokenEndpointHttpStatus200, ConditionResult.FAILURE, "RFC6749-5.1");
		this.callAndContinueOnFailure(CheckTokenEndpointReturnedJsonContentType, ConditionResult.FAILURE, "RFC6749-5.1");
		this.callAndContinueOnFailure(CheckTokenEndpointCacheHeaders, ConditionResult.FAILURE, "RFC6749-5.1");
		this.callAndStopOnFailure(CheckIfTokenEndpointResponseError);

		this.callAndStopOnFailure(ExtractAccessTokenFromTokenResponse);

		if (this.isDpop) {
			this.callAndContinueOnFailure(CheckTokenTypeIsDpop, ConditionResult.FAILURE, "DPOP-5");
		} else {
			this.callAndContinueOnFailure(
				CheckTokenTypeIsBearer,
				ConditionResult.FAILURE,
				"FAPI-R-6.2.2-1",
				"FAPI1-BASE-6.2.2-1",
			);
		}
		this.callAndContinueOnFailure(
			EnsureMinimumAccessTokenEntropy,
			ConditionResult.FAILURE,
			"FAPI-R-5.2.2-16",
			"FAPI1-BASE-5.2.2-16",
		);
		this.callAndContinueOnFailure(
			EnsureAccessTokenContainsAllowedCharactersOnly,
			ConditionResult.FAILURE,
			"RFC6749-A.12",
		);
		this.callAndContinueOnFailure(
			ExtractExpiresInFromTokenEndpointResponse,
			ConditionResult.WARNING,
			"RFC6749-6",
			"RFC6749-5.1",
		);
		this.call(
			this.condition(ValidateExpiresIn)
				.skipIfObjectMissing("expires_in")
				.requirement("RFC6749-5.1")
				.dontStopOnFailure(),
		);

		this.callAndContinueOnFailure(EnsureAccessTokenValuesAreDifferent, ConditionResult.INFO);

		this.call(
			this.condition(ValidateIdTokenFromTokenResponseEncryption)
				.skipIfObjectMissing("client_jwks")
				.onSkip(ConditionResult.INFO)
				.onFail(ConditionResult.INFO)
				.dontStopOnFailure(),
		);
		this.callAndContinueOnFailure(ExtractIdTokenFromTokenResponse, ConditionResult.INFO);

		// It's perfectly legal to NOT return a new refresh token; if the server didn't then
		// 'refresh_token' in the environment will be left containing the old (still valid)
		// token. We use that token later to test the refresh token is bound to the client
		// correctly.
		this.callAndContinueOnFailure(ExtractRefreshTokenFromTokenResponse, ConditionResult.INFO);

		this.call(
			this.condition(EnsureMinimumRefreshTokenLength)
				.skipIfElementMissing("token_endpoint_response", "refresh_token")
				.requirement("RFC6749-10.10")
				.dontStopOnFailure(),
		);

		this.call(
			this.condition(EnsureMinimumRefreshTokenEntropy)
				.skipIfElementMissing("token_endpoint_response", "refresh_token")
				.requirement("RFC6749-10.10")
				.dontStopOnFailure(),
		);

		//compare only when refresh response contains an id_token
		this.call(
			this.condition(CompareIdTokenClaims)
				.skipIfObjectMissing("second_id_token")
				.requirement("OIDCC-12.2")
				.dontStopOnFailure(),
		);

		this.call(this.exec().endBlock());
	}
}
