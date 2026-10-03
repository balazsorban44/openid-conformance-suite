import { AbstractConditionSequence } from "../../framework/index.ts";

export class OIDCCValidateClientAuthenticationWithNone extends AbstractConditionSequence {
	override evaluate(): void {
		//do nothing for now
		//we don't know if this should actually perform some checks, yet.
		//we may update this class once we clarify that
		//this class may also turn out to be unnecessary
		//but we don't know that yet because the tests are still incomplete
	}
}
