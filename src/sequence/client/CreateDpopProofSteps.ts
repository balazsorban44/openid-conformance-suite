import { AbstractConditionSequence, ConditionResult, type ConditionSequence } from "../../framework/index.ts";
import { AddDpopHeaderForParEndpointRequest } from "../../condition/client/AddDpopHeaderForParEndpointRequest.ts";
import { AddDpopHeaderForResourceEndpointRequest } from "../../condition/client/AddDpopHeaderForResourceEndpointRequest.ts";
import { AddDpopHeaderForTokenEndpointRequest } from "../../condition/client/AddDpopHeaderForTokenEndpointRequest.ts";
import { CreateDpopClaims } from "../../condition/client/CreateDpopClaims.ts";
import { CreateDpopHeader } from "../../condition/client/CreateDpopHeader.ts";
import { EnsureDpopNonceContainsAllowedCharactersOnly } from "../../condition/client/EnsureDpopNonceContainsAllowedCharactersOnly.ts";
import { SetDpopAccessTokenHash } from "../../condition/client/SetDpopAccessTokenHash.ts";
import { SetDpopHtmHtuForParEndpoint } from "../../condition/client/SetDpopHtmHtuForParEndpoint.ts";
import { SetDpopHtmHtuForResourceEndpoint } from "../../condition/client/SetDpopHtmHtuForResourceEndpoint.ts";
import { SetDpopHtmHtuForTokenEndpoint } from "../../condition/client/SetDpopHtmHtuForTokenEndpoint.ts";
import { SetDpopProofNonceForResourceEndpoint } from "../../condition/client/SetDpopProofNonceForResourceEndpoint.ts";
import { SetDpopProofNonceForAuthorizationServer } from "../../condition/client/SetDpopProofNonceForAuthorizationServer.ts";
import { SignDpopProof } from "../../condition/client/SignDpopProof.ts";

/** Java: public enum DPOP_PROOF_TYPE { TOKEN, PAR, RESOURCE } (enums are not erasable syntax, so a const object) */
export const DPOP_PROOF_TYPE = { TOKEN: "TOKEN", PAR: "PAR", RESOURCE: "RESOURCE" } as const;
export type DPOP_PROOF_TYPE = (typeof DPOP_PROOF_TYPE)[keyof typeof DPOP_PROOF_TYPE];

export class CreateDpopProofSteps extends AbstractConditionSequence {
	/** Java: CreateDpopProofSteps.DPOP_PROOF_TYPE */
	static readonly DPOP_PROOF_TYPE = DPOP_PROOF_TYPE;

	private proofType: DPOP_PROOF_TYPE = DPOP_PROOF_TYPE.TOKEN;

	constructor(proofType: DPOP_PROOF_TYPE) {
		super();
		this.proofType = proofType;
	}

	static createParEndpointDpopSteps(): ConditionSequence {
		return new CreateDpopProofSteps(DPOP_PROOF_TYPE.PAR);
	}

	static createTokenEndpointDpopSteps(): ConditionSequence {
		return new CreateDpopProofSteps(DPOP_PROOF_TYPE.TOKEN);
	}

	static createResourceEndpointDpopSteps(): ConditionSequence {
		return new CreateDpopProofSteps(DPOP_PROOF_TYPE.RESOURCE);
	}

	override evaluate(): void {
		this.callAndStopOnFailure(CreateDpopHeader);
		this.callAndStopOnFailure(CreateDpopClaims);

		// Add endpoint specific DPOP params
		switch (this.proofType) {
			case DPOP_PROOF_TYPE.TOKEN:
				this.callAndStopOnFailure(SetDpopHtmHtuForTokenEndpoint);
				this.callAndContinueOnFailure(SetDpopProofNonceForAuthorizationServer, ConditionResult.INFO);
				break;

			case DPOP_PROOF_TYPE.PAR:
				this.callAndStopOnFailure(SetDpopHtmHtuForParEndpoint);
				this.callAndContinueOnFailure(SetDpopProofNonceForAuthorizationServer, ConditionResult.INFO);
				break;

			case DPOP_PROOF_TYPE.RESOURCE:
				this.callAndStopOnFailure(SetDpopHtmHtuForResourceEndpoint);
				this.callAndStopOnFailure(SetDpopAccessTokenHash);
				this.callAndContinueOnFailure(SetDpopProofNonceForResourceEndpoint, ConditionResult.INFO);
				break;
		}

		this.callAndContinueOnFailure(EnsureDpopNonceContainsAllowedCharactersOnly, ConditionResult.FAILURE, "DPOP-8.1");
		this.callAndStopOnFailure(SignDpopProof);

		// Add DPOP header to request
		switch (this.proofType) {
			case DPOP_PROOF_TYPE.TOKEN:
				this.callAndStopOnFailure(AddDpopHeaderForTokenEndpointRequest);
				break;

			case DPOP_PROOF_TYPE.PAR:
				this.callAndStopOnFailure(AddDpopHeaderForParEndpointRequest);
				break;

			case DPOP_PROOF_TYPE.RESOURCE:
				this.callAndStopOnFailure(AddDpopHeaderForResourceEndpointRequest);
				break;
		}
	}
}
