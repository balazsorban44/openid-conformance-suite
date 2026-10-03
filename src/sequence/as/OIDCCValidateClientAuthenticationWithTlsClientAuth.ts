import { AbstractConditionSequence, ConditionResult } from "../../framework/index.ts";
import { CheckForClientCertificate } from "../../condition/as/CheckForClientCertificate.ts";
import { EnsureMTLSRequestContainsValidClientId } from "../../condition/as/EnsureMTLSRequestContainsValidClientId.ts";
import { ExtractClientCertificateFromRequestHeaders } from "../../condition/as/ExtractClientCertificateFromRequestHeaders.ts";
import { ValidateClientCertificateForTlsClientAuth } from "../../condition/as/ValidateClientCertificateForTlsClientAuth.ts";

export class OIDCCValidateClientAuthenticationWithTlsClientAuth extends AbstractConditionSequence {
	override evaluate(): void {
		this.callAndContinueOnFailure(EnsureMTLSRequestContainsValidClientId, ConditionResult.FAILURE, "RFC8705-2");
		this.callAndStopOnFailure(ExtractClientCertificateFromRequestHeaders);
		this.callAndStopOnFailure(CheckForClientCertificate);
		this.callAndStopOnFailure(ValidateClientCertificateForTlsClientAuth, "RFC8705-2.1.2");
	}
}
