import { AbstractCondition } from "../../framework/index.ts";
import { PEMFormatter } from "../util/PEMFormatter.ts";

export abstract class AbstractValidateMTLSCertificatesHeader extends AbstractCondition {
	protected validateMTLSCertificatesHeader(
		certString: string | null,
		keyString: string | null,
		caString: string | null,
	): void {
		if (!certString || !keyString) {
			throw this.error("Couldn't find TLS client certificate or key for MTLS");
		}

		if (!caString) {
			// Not an error; we just won't send a CA chain
			this.log("No certificate authority found for MTLS");
		}

		this.validatePEMHeader(certString, keyString, caString);

		this.logSuccess("MTLS certificates header is valid");
	}

	private validatePEMHeader(certString: string, keyString: string, caString: string | null): void {
		const certHeaderListExpect = ["-----BEGIN CERTIFICATE-----", "-----BEGIN RSA CERTIFICATE-----"];

		const keyHeaderListExpect = [
			"-----BEGIN PRIVATE KEY-----",
			"-----BEGIN RSA PRIVATE KEY-----",
			"-----BEGIN EC PRIVATE KEY-----",
		];

		const certHeaderList = PEMFormatter.extractPEMHeader(certString);
		for (const certHeader of certHeaderList) {
			if (!certHeaderListExpect.includes(certHeader)) {
				throw this.error(
					"You uploaded something that begins " +
						certHeader +
						", but you need to provide a certificate which would begin with " +
						certHeaderListExpect.join(", "),
				);
			}
		}

		const keyHeaderList = PEMFormatter.extractPEMHeader(keyString);
		for (const keyHeader of keyHeaderList) {
			if (!keyHeaderListExpect.includes(keyHeader)) {
				throw this.error(
					"You uploaded something that begins " +
						keyHeader +
						", but you need to provide a private key which would begin with " +
						keyHeaderListExpect.join(", "),
				);
			}
		}

		if (caString != null) {
			const caHeaderList = PEMFormatter.extractPEMHeader(caString);
			for (const caHeader of caHeaderList) {
				if (!certHeaderListExpect.includes(caHeader)) {
					throw this.error(
						"You uploaded something that begins " +
							caHeader +
							", but you need to provide a certificate authority which would begin with " +
							certHeaderListExpect.join(", "),
					);
				}
			}
		}
	}
}
