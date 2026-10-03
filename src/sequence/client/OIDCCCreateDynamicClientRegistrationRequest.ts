import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { AddAuthorizationCodeGrantTypeToDynamicRegistrationRequest } from "../../condition/client/AddAuthorizationCodeGrantTypeToDynamicRegistrationRequest.ts";
import { AddClientNameToDynamicRegistrationRequest } from "../../condition/client/AddClientNameToDynamicRegistrationRequest.ts";
import { AddContactsToDynamicRegistrationRequest } from "../../condition/client/AddContactsToDynamicRegistrationRequest.ts";
import { AddImplicitGrantTypeToDynamicRegistrationRequest } from "../../condition/client/AddImplicitGrantTypeToDynamicRegistrationRequest.ts";
import { AddPublicJwksToDynamicRegistrationRequest } from "../../condition/client/AddPublicJwksToDynamicRegistrationRequest.ts";
import { AddRedirectUriToDynamicRegistrationRequest } from "../../condition/client/AddRedirectUriToDynamicRegistrationRequest.ts";
import { AddResponseTypesArrayToDynamicRegistrationRequestFromEnvironment } from "../../condition/client/AddResponseTypesArrayToDynamicRegistrationRequestFromEnvironment.ts";
import { AddTokenEndpointAuthMethodToDynamicRegistrationRequestFromEnvironment } from "../../condition/client/AddTokenEndpointAuthMethodToDynamicRegistrationRequestFromEnvironment.ts";
import { CreateEmptyDynamicRegistrationRequest } from "../../condition/client/CreateEmptyDynamicRegistrationRequest.ts";
import { GenerateRS256ClientJWKs } from "../../condition/client/GenerateRS256ClientJWKs.ts";
import { CheckDistinctKeyIdValueInClientJWKs } from "../../condition/common/CheckDistinctKeyIdValueInClientJWKs.ts";
import type { ResponseType } from "../../variant/ResponseType.ts";

export class OIDCCCreateDynamicClientRegistrationRequest extends AbstractConditionSequence {
	private readonly responseType: ResponseType;

	constructor(responseType: ResponseType) {
		super();
		this.responseType = responseType;
	}

	override evaluate(): void {
		this.callAndStopOnFailure(GenerateRS256ClientJWKs);

		this.callAndContinueOnFailure(CheckDistinctKeyIdValueInClientJWKs, ConditionResult.FAILURE, "RFC7517-4.5");

		// create basic dynamic registration request
		this.callAndStopOnFailure(CreateEmptyDynamicRegistrationRequest);
		this.callAndStopOnFailure(AddClientNameToDynamicRegistrationRequest);

		if (this.responseType.includesCode()) {
			this.callAndStopOnFailure(AddAuthorizationCodeGrantTypeToDynamicRegistrationRequest);
		}

		if (this.responseType.includesIdToken() || this.responseType.includesToken()) {
			this.callAndStopOnFailure(AddImplicitGrantTypeToDynamicRegistrationRequest);
		}

		this.callAndStopOnFailure(AddPublicJwksToDynamicRegistrationRequest, "RFC7591-2");
		this.callAndStopOnFailure(AddTokenEndpointAuthMethodToDynamicRegistrationRequestFromEnvironment);
		this.callAndStopOnFailure(AddResponseTypesArrayToDynamicRegistrationRequestFromEnvironment);
		this.callAndStopOnFailure(AddRedirectUriToDynamicRegistrationRequest);

		this.callAndContinueOnFailure(AddContactsToDynamicRegistrationRequest, ConditionResult.INFO);
	}
}
