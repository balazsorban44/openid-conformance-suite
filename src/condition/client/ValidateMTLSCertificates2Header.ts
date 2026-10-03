import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractValidateMTLSCertificatesHeader } from "./AbstractValidateMTLSCertificatesHeader.ts";

export class ValidateMTLSCertificates2Header extends AbstractValidateMTLSCertificatesHeader {
	static override pre: EnvironmentRequirements = { required: ["config"] };

	override evaluate(env: Environment): Environment {
		// mutual_tls_authentication
		const certString = env.getString("config", "mtls2.cert");
		const keyString = env.getString("config", "mtls2.key");
		const caString = env.getString("config", "mtls2.ca");
		this.validateMTLSCertificatesHeader(certString, keyString, caString);
		return env;
	}
}
