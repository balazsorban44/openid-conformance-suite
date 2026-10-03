import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureIncomingTls12WithSecureCipherOrTls13 extends AbstractCondition {
	// as per SSL_PROTOCOL in https://httpd.apache.org/docs/current/mod/mod_ssl.html
	private static readonly TLS_12 = "TLSv1.2";
	private static readonly TLS_13 = "TLSv1.3";

	static override pre: EnvironmentRequirements = { required: ["client_request"] };

	override evaluate(env: Environment): Environment {
		const protocol = env.getString("client_request", "headers.x-ssl-protocol");

		if (!protocol) {
			throw this.error("TLS Protocol not found; this header should have been set by the apache proxy");
		}

		if (protocol === EnsureIncomingTls12WithSecureCipherOrTls13.TLS_12) {
			const cipher = env.getString("client_request", "headers.x-ssl-cipher");
			const recommended = this.getRecomendedCiphers();

			if (!recommended.includes(cipher as string)) {
				// "actual" here uses the openssl names instead of the standard iana ones, which is annoying but
				// apache can only give us the openssl ones: https://httpd.apache.org/docs/current/mod/mod_ssl.html
				// and there doesn't seem to be an easy way to map back: https://stackoverflow.com/questions/63491644/openssl-1-1-get-a-cipher-suite-by-the-iana-id
				// https://testssl.sh/openssl-iana.mapping.html
				// openssl ciphers -V outputs the hex codes and openssl names, in theory we could get the hex code then lookup in org.bouncycastle.crypto.tls.CipherSuite to convert to the standard name
				throw this.error(
					"TLS 1.2 in use and cipher is not one recommended by BCP195",
					args("expected", recommended, "actual", cipher),
				);
			}
			this.logSuccess(
				"TLS 1.2 in use and cipher is one recommended by BCP195",
				args("recommended", recommended, "actual", cipher),
			);
			return env;
		} else if (protocol === EnsureIncomingTls12WithSecureCipherOrTls13.TLS_13) {
			this.logSuccess("Found TLS 1.3 connection");
			return env;
		} else {
			throw this.error("TLS version is neither 1.2 nor 1.3", args("actual", protocol));
		}
	}

	protected getRecomendedCiphers(): string[] {
		// List of recommended ciphers from the older version of BCP195 (RFC7525); note that apache uses the OpenSSL cipher name
		// unlike the constants found in the CipherSuite enum used by DisallowInsecureCipher which
		// uses the IANA name.
		//
		// See https://ciphersuite.info/cs/ for mappings.
		return [
			"DHE-RSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"DHE-RSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
		];
	}
}
