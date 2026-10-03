import { AbstractConditionSequence } from "../../framework/index.ts";
import { AddCodeChallengeToAuthorizationEndpointRequest } from "../../condition/client/AddCodeChallengeToAuthorizationEndpointRequest.ts";
import { CreateRandomCodeVerifier } from "../../condition/client/CreateRandomCodeVerifier.ts";
import { CreateS256CodeChallenge } from "../../condition/client/CreateS256CodeChallenge.ts";

export class SetupPkceAndAddToAuthorizationRequest extends AbstractConditionSequence {
	override evaluate(): void {
		this.call(this.condition(CreateRandomCodeVerifier).requirement("RFC7636-4.1"));
		this.call(this.exec().exposeEnvironmentString("code_verifier"));
		this.call(this.condition(CreateS256CodeChallenge).requirement("RFC7636-4.2"));
		this.call(this.exec().exposeEnvironmentString("code_challenge").exposeEnvironmentString("code_challenge_method"));
		this.call(this.condition(AddCodeChallengeToAuthorizationEndpointRequest).requirement("RFC7636-4.3"));
	}
}
