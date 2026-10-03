import { X509Certificate } from "node:crypto";
import {
	AbstractCondition,
	args,
	isJsonArray,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JWKUtil, ParseException } from "../../util/JWKUtil.ts";

export class ValidateClientCertificateForSelfSignedTlsClientAuth extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client_certificate", "client"] };

	override evaluate(env: Environment): Environment {
		const certInfo = env.getObject("client_certificate") as JsonObject;
		const client = env.getObject("client") as JsonObject;
		let expectedCertificate: X509Certificate;
		const certPem = OIDFJSON.getString(certInfo["pem"]);
		try {
			expectedCertificate = new X509Certificate(Buffer.from(certPem));
		} catch (ex) {
			throw this.error("Invalid certificate", ex, args("certificate_pem", certPem));
		}
		const clientJwksElement = client["jwks"];
		if (!isJsonObject(clientJwksElement)) {
			// Gson getAsJsonObject()
			throw new Error("Not a JSON Object: " + JSON.stringify(clientJwksElement));
		}
		const clientJwks = clientJwksElement;
		try {
			const jwkSet = JWKUtil.parseJWKSet(JSON.stringify(clientJwks));
			for (const jwk of jwkSet.keys) {
				//Also note that Section 4.7 of
				//   [RFC7517] requires that the key in the first certificate of the "x5c"
				//   parameter match the public key represented by those other members of
				//   the JWK.
				const x5c = jwk["x5c"];
				if (isJsonArray(x5c) && x5c.length > 0) {
					// jwk.getParsedX509CertChain().get(0) (parseJWKSet already validated the chain)
					const cert = new X509Certificate(Buffer.from(OIDFJSON.getString(x5c[0]), "base64"));
					if (expectedCertificate.raw.equals(cert.raw)) {
						this.logSuccess("Valid client certificate found in request", args("certificate", certInfo));
						return env;
					}
				}
			}
		} catch (e) {
			if (!(e instanceof ParseException)) {
				throw e;
			}
			throw this.error("Failed to parse client jwks", e);
		}
		throw this.error(
			"Could not find a certificate in client jwks matching the one in the request",
			args("jwks", clientJwks, "certificate_in_request", certInfo),
		);
	}
}
