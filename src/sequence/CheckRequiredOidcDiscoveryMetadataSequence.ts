import { AbstractConditionSequence, ConditionResult, type ConditionClass } from "../framework/index.ts";
import { CheckDiscEndpointAuthorizationEndpoint } from "../condition/client/CheckDiscEndpointAuthorizationEndpoint.ts";
import { CheckDiscEndpointScopesSupportedContainsOpenId } from "../condition/client/CheckDiscEndpointScopesSupportedContainsOpenId.ts";
import { CheckDiscEndpointSubjectTypesSupported } from "../condition/client/CheckDiscEndpointSubjectTypesSupported.ts";
import { CheckDiscEndpointTokenEndpoint } from "../condition/client/CheckDiscEndpointTokenEndpoint.ts";
import { CheckJwksUri } from "../condition/client/CheckJwksUri.ts";

/**
 * Checks the provider metadata fields OpenID Connect Discovery 1.0 section 3 marks as REQUIRED.
 *
 * <p>Only usable where the server under test is an OpenID Provider; an RFC 8414 authorization
 * server that does not implement OpenID Connect has no such obligation.
 *
 * <p>{@code issuer} is deliberately not included: every caller already checks it, and the check
 * differs between the OpenID Connect and plain OAuth flavours of the discovery document.
 *
 * <p>The {@code response_types_supported} and {@code id_token_signing_alg_values_supported}
 * checks are supplied by the caller, as the acceptable values are profile specific (FAPI, for
 * example, requires PS256/ES256 where plain OpenID Connect requires RS256). Pass {@code null}
 * for either where the caller already performs its own check, to avoid checking it twice.
 */
export class CheckRequiredOidcDiscoveryMetadataSequence extends AbstractConditionSequence {
	private readonly responseTypesSupportedCheck: ConditionClass | null;
	private readonly idTokenSigningAlgValuesSupportedCheck: ConditionClass | null;
	// The requirements fields are prefixed with an underscore: the builder methods keep the Java names, which a
	// TypeScript class cannot share with a field
	private _responseTypesSupportedRequirements: string[] = ["OIDCD-3"];
	private _idTokenSigningAlgValuesSupportedRequirements: string[] = ["OIDCD-3"];
	private checkAuthorizationEndpoint = true;

	constructor(
		responseTypesSupportedCheck: ConditionClass | null,
		idTokenSigningAlgValuesSupportedCheck: ConditionClass | null,
	) {
		super();
		this.responseTypesSupportedCheck = responseTypesSupportedCheck;
		this.idTokenSigningAlgValuesSupportedCheck = idTokenSigningAlgValuesSupportedCheck;
	}

	responseTypesSupportedRequirements(...requirements: string[]): this {
		this._responseTypesSupportedRequirements = requirements;
		return this;
	}

	idTokenSigningAlgValuesSupportedRequirements(...requirements: string[]): this {
		this._idTokenSigningAlgValuesSupportedRequirements = requirements;
		return this;
	}

	/**
	 * For a CIBA-only provider, which has no authorization endpoint and hence no
	 * {@code response_types_supported} either.
	 */
	withoutAuthorizationEndpointCheck(): this {
		this.checkAuthorizationEndpoint = false;
		return this;
	}

	override evaluate(): void {
		if (this.checkAuthorizationEndpoint) {
			this.callAndContinueOnFailure(CheckDiscEndpointAuthorizationEndpoint, ConditionResult.FAILURE, "OIDCD-3");
		}

		this.callAndContinueOnFailure(CheckDiscEndpointTokenEndpoint, ConditionResult.FAILURE, "OIDCD-3");

		this.callAndContinueOnFailure(CheckJwksUri, ConditionResult.FAILURE, "OIDCD-3");

		if (this.checkAuthorizationEndpoint && this.responseTypesSupportedCheck != null) {
			this.callAndContinueOnFailure(
				this.responseTypesSupportedCheck,
				ConditionResult.FAILURE,
				...this._responseTypesSupportedRequirements,
			);
		}

		this.callAndContinueOnFailure(CheckDiscEndpointSubjectTypesSupported, ConditionResult.FAILURE, "OIDCD-3");

		if (this.idTokenSigningAlgValuesSupportedCheck != null) {
			this.callAndContinueOnFailure(
				this.idTokenSigningAlgValuesSupportedCheck,
				ConditionResult.FAILURE,
				...this._idTokenSigningAlgValuesSupportedRequirements,
			);
		}

		// scopes_supported is only RECOMMENDED, but an OpenID Provider that publishes it must
		// list the openid scope it necessarily supports
		this.call(
			this.condition(CheckDiscEndpointScopesSupportedContainsOpenId)
				.skipIfElementMissing("server", "scopes_supported")
				.onFail(ConditionResult.FAILURE)
				.onSkip(ConditionResult.WARNING)
				.requirement("OIDCD-3")
				.dontStopOnFailure(),
		);
	}
}
