import { X509Certificate } from "node:crypto";
import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";
import { GeneralName, getSubjectAlternativeNames, getSubjectX500PrincipalName } from "../../util/jdk/x509.ts";

export class ExtractClientCertificateFromRequestHeaders extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["client_certificate"] };

	override evaluate(env: Environment): Environment {
		// Remove any certificate from a previous connection
		env.removeObject("client_certificate");

		const certStr = env.getString("token_endpoint_request", "headers.x-ssl-cert");

		if (certStr == null) {
			throw this.error("Client certificate not found; likely the non-mtls version of the endpoint was called");
		}

		if (certStr === "(null)") {
			// "(null)" is particular behaviour of apache's request header, as used in our ingress via:
			// "RequestHeader set X-Ssl-Cert "%{SSL_CLIENT_CERT}s"
			throw this.error(
				"Client certificate not found; the client did not supply a MTLS certification to the endpoint. In some cases this may be because the client is, incorrectly, configured to supply a TLS certificate only if the server explicitly requires a certificate at the TLS level.",
			);
		}

		let certInfo: JsonObject;
		try {
			// pre-process the cert string for the PEM parser
			const certPem = certStr.replace(/\s+(?!CERTIFICATE-----)/g, "\n");

			const cert = new X509Certificate(certPem);

			certInfo = {};
			certInfo["cert"] = certStr;
			certInfo["pem"] = certPem;

			const subjectInfo: JsonObject = {};
			subjectInfo["dn"] = getSubjectX500PrincipalName(cert);
			certInfo["subject"] = subjectInfo;

			const sanDnsNames: JsonArray = [];
			const sanUris: JsonArray = [];
			const sanIPs: JsonArray = [];
			const sanEmails: JsonArray = [];

			const altNames = getSubjectAlternativeNames(cert);
			for (const altName of altNames) {
				if (altName.length < 2) {
					continue;
				}
				const sanValue = String(altName[1]);
				switch (altName[0]) {
					case GeneralName.dNSName:
						sanDnsNames.push(sanValue);
						break;
					case GeneralName.iPAddress:
						sanIPs.push(sanValue);
						break;
					case GeneralName.uniformResourceIdentifier:
						sanUris.push(sanValue);
						break;
					case GeneralName.rfc822Name:
						sanEmails.push(sanValue);
						break;
				}
			}

			certInfo["sanDnsNames"] = sanDnsNames;
			certInfo["sanUris"] = sanUris;
			certInfo["sanIPs"] = sanIPs;
			certInfo["sanEmails"] = sanEmails;
		} catch (e) {
			throw this.error("Error parsing certificate", e, args("cert", certStr));
		}

		env.putObject("client_certificate", certInfo);

		this.logSuccess("Extracted client certificate", args("client_certificate", certInfo));

		return env;
	}
}
