import {
	AbstractCondition,
	args,
	has,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";
import { inetAddressBytes } from "../../util/jdk/inet.ts";
import { InvalidNameException, parseLdapName, rdnEquals, type ParsedRdn } from "../../util/jdk/ldap.ts";

export class ValidateClientCertificateForTlsClientAuth extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client_certificate", "client"] };

	override evaluate(env: Environment): Environment {
		const certIfo = env.getObject("client_certificate") as JsonObject;
		const client = env.getObject("client") as JsonObject;

		let fieldCount = 0;

		/*
		A client using the
		"tls_client_auth" authentication method MUST use exactly one of the
		below metadata parameters to indicate the certificate subject value
		that the authorization server is to expect when authenticating the
		respective client.
		Also https://tools.ietf.org/html/rfc8705#section-2.1
			Only one subject name value of any type is used for each
			client.
		*/
		if (has(client, "tls_client_auth_subject_dn")) {
			fieldCount++;
		}
		if (has(client, "tls_client_auth_san_dns")) {
			fieldCount++;
		}
		if (has(client, "tls_client_auth_san_uri")) {
			fieldCount++;
		}
		if (has(client, "tls_client_auth_san_ip")) {
			fieldCount++;
		}
		if (has(client, "tls_client_auth_san_email")) {
			fieldCount++;
		}

		if (fieldCount !== 1) {
			throw this.error(
				"Client must have only one of " +
					"tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, " +
					"tls_client_auth_san_ip and tls_client_auth_san_email metadata values set" +
					"(cannot have more than one set)",
				args("client", client),
			);
		}

		if (has(client, "tls_client_auth_subject_dn")) {
			const expectedDnString = OIDFJSON.getString(client["tls_client_auth_subject_dn"]);
			const actualDnString = OIDFJSON.getString((certIfo["subject"] as JsonObject)["dn"]);
			let expectedRDNs: ParsedRdn[];
			let actualRDNs: ParsedRdn[];
			try {
				expectedRDNs = parseLdapName(expectedDnString);
				actualRDNs = parseLdapName(actualDnString);
			} catch (ex) {
				if (ex instanceof InvalidNameException) {
					throw this.error(
						"Invalid subject dn",
						ex,
						args(
							"expected_dn",
							OIDFJSON.getString(client["tls_client_auth_subject_dn"]),
							"actual_dn",
							OIDFJSON.getString((certIfo["subject"] as JsonObject)["dn"]),
						),
					);
				}
				throw ex;
			}

			//Compare DNs independent of RDN element order. Java and Openssl order them differently so 'equals' won't work
			if (
				expectedRDNs.length === actualRDNs.length &&
				actualRDNs.every((actual) => expectedRDNs.some((expected) => rdnEquals(expected, actual)))
			) {
				this.logSuccess("Certificate subject dn is valid", args("subject_dn", actualDnString));
				return env;
			} else {
				throw this.error(
					"Certificate subject dn in request does not match expected tls_client_auth_subject_dn",
					args("expected", expectedDnString, "actual", actualDnString),
				);
			}
		}

		if (has(client, "tls_client_auth_san_dns")) {
			const expected = OIDFJSON.getString(client["tls_client_auth_san_dns"]);
			const actualValues = certIfo["sanDnsNames"] as JsonArray;
			if (this.jsonArrayContainsCaseInsensitive(actualValues, expected)) {
				this.logSuccess(
					"Certificate contains the expected tls_client_auth_san_dns",
					args("expected", expected, "actual", actualValues),
				);
				return env;
			} else {
				throw this.error(
					"Certificate does not contain the configured tls_client_auth_san_dns, " +
						"dNSName subject alternative name, entry",
					args("expected", expected, "actual", actualValues),
				);
			}
		}

		if (has(client, "tls_client_auth_san_uri")) {
			const expected = OIDFJSON.getString(client["tls_client_auth_san_uri"]);
			const actualValues = certIfo["sanUris"] as JsonArray;
			if (this.checkSanUri(actualValues, expected)) {
				this.logSuccess(
					"Certificate contains the expected tls_client_auth_san_uri",
					args("expected", expected, "actual", actualValues),
				);
				return env;
			} else {
				throw this.error(
					"Certificate does not contain the configured tls_client_auth_san_uri," +
						" uniformResourceIdentifier subject alternative name, entry",
					args("expected", expected, "actual", actualValues),
				);
			}
		}

		if (has(client, "tls_client_auth_san_ip")) {
			const expected = OIDFJSON.getString(client["tls_client_auth_san_ip"]);
			const actualValues = certIfo["sanIPs"] as JsonArray;
			if (this.checkSanIP(actualValues, expected)) {
				this.logSuccess(
					"Certificate contains the expected tls_client_auth_san_ip",
					args("expected", expected, "actual", actualValues),
				);
				return env;
			} else {
				throw this.error(
					"Certificate does not contain the configured tls_client_auth_san_ip, " +
						"iPAddress subject alternative name, entry",
					args("expected", expected, "actual", actualValues),
				);
			}
		}

		if (has(client, "tls_client_auth_san_email")) {
			const expected = OIDFJSON.getString(client["tls_client_auth_san_email"]);
			const actualValues = certIfo["sanEmails"] as JsonArray;
			if (this.jsonArrayContainsCaseInsensitive(actualValues, expected)) {
				this.logSuccess(
					"Certificate contains the expected tls_client_auth_san_email",
					args("expected", expected, "actual", actualValues),
				);
				return env;
			} else {
				throw this.error(
					"Certificate does not contain the configured tls_client_auth_san_email, " +
						"rfc822Name subject alternative name, entry",
					args("expected", expected, "actual", actualValues),
				);
			}
		}

		throw this.error(
			"Client must contain one of tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri," +
				"tls_client_auth_san_ip or tls_client_auth_san_email metadata parameters",
		);
	}

	checkSanUri(jsonElements: JsonArray, expected: string): boolean {
		// UPSTREAM-NOTE: java.net.URI is approximated with the WHATWG URL parser (absolute URIs only, equality on the
		// normalised form)
		let expectedURI: URL;
		try {
			expectedURI = new URL(expected);
		} catch {
			throw this.error("Invalid expected URI", args("expected_uri", expected));
		}

		for (const element of jsonElements) {
			let uri: URL;
			try {
				uri = new URL(OIDFJSON.getString(element));
			} catch {
				//TODO this one might be an invalid uri but in theory there may be another valid SAN value that will match the configured
				// should we throw an error or not?
				throw this.error("Invalid URI value in subject alternative names", args("invalid_uri", element));
			}
			if (expectedURI.href === uri.href) {
				return true;
			}
		}

		return false;
	}

	checkSanIP(jsonElements: JsonArray, expected: string): boolean {
		const expectedAddress = inetAddressBytes(expected);

		for (const element of jsonElements) {
			const address = inetAddressBytes(OIDFJSON.getString(element));
			if (expectedAddress.length === address.length && expectedAddress.every((b, i) => b === address[i])) {
				return true;
			}
		}

		return false;
	}

	private jsonArrayContainsCaseInsensitive(jsonElements: JsonArray, expectedValue: string): boolean {
		for (const element of jsonElements) {
			const elementValue = OIDFJSON.getString(element);
			if (elementValue.toLowerCase() === expectedValue.toLowerCase()) {
				return true;
			}
		}
		return false;
	}
}
