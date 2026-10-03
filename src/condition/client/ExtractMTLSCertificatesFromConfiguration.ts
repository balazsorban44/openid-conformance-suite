import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { PEMFormatter } from "../util/PEMFormatter.ts";

export class ExtractMTLSCertificatesFromConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["config"] };
	static override post: EnvironmentRequirements = { required: ["mutual_tls_authentication"] };

	override evaluate(env: Environment): Environment {
		// mutual_tls_authentication

		let certString = env.getString("config", "mtls.cert");
		let keyString = env.getString("config", "mtls.key");
		let caString = env.getString("config", "mtls.ca");

		if (!certString || !keyString) {
			throw this.error(
				"'mtls.cert' and 'mtls.key' fields are missing from the " +
					"'TLS certificates for client (used to make MTLS connections)' section in the test configuration",
			);
		}

		if (!caString) {
			// Not an error; we just won't send a CA chain
			this.log("No certificate authority found for MTLS");
		}

		try {
			certString = PEMFormatter.stripPEM(certString);

			keyString = PEMFormatter.stripPEM(keyString);

			if (caString != null) {
				caString = PEMFormatter.stripPEM(caString);
			}
		} catch (e) {
			// Java: IllegalArgumentException
			throw this.error(
				"Couldn't decode certificate, key, or CA chain from Base64",
				e,
				args("cert", certString, "key", keyString, "ca", caString || null),
			);
		}

		const mtls: JsonObject = {};
		mtls["cert"] = certString;
		mtls["key"] = keyString;
		if (caString != null) {
			mtls["ca"] = caString;
		}

		env.putObject("mutual_tls_authentication", mtls);

		this.logSuccess("Mutual TLS authentication credentials loaded", mtls);

		return env;
	}
}
