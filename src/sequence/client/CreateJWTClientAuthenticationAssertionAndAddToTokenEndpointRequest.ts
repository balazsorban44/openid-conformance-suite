import { AbstractConditionSequence } from "../../framework/index.ts";
import { AddClientAssertionToRequest } from "../../condition/client/AddClientAssertionToRequest.ts";
import { CreateClientAuthenticationAssertionClaims } from "../../condition/client/CreateClientAuthenticationAssertionClaims.ts";
import { SignClientAuthenticationAssertion } from "../../condition/client/SignClientAuthenticationAssertion.ts";

export class CreateJWTClientAuthenticationAssertionAndAddToTokenEndpointRequest extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndStopOnFailure(CreateClientAuthenticationAssertionClaims);

		this.callAndStopOnFailure(SignClientAuthenticationAssertion);

		this.callAndStopOnFailure(AddClientAssertionToRequest);
	}
}
