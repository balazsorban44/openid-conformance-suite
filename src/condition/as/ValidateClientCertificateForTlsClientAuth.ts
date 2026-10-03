import { isIP } from "node:net";
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

/**
 * The equivalent of javax.naming.ldap.Rdn for the purpose of comparing DNs: a set of attribute type/value pairs.
 * Types are compared case-insensitively and string values are compared by their unescaped, upper-cased value.
 */
interface ParsedRdn {
	/** normalised "type=value" entries, sorted */
	entries: string[];
}

class InvalidNameException extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidNameException";
	}
}

/**
 * Parses an RFC 2253 distinguished name (what javax.naming.ldap.LdapName does), throws InvalidNameException if
 * the name is not valid.
 */
function parseLdapName(dn: string): ParsedRdn[] {
	const rdns: ParsedRdn[] = [];
	let pos = 0;
	const len = dn.length;

	if (dn.trim().length === 0) {
		return rdns;
	}

	for (;;) {
		const entries: string[] = [];
		for (;;) {
			// attribute type
			const eq = dn.indexOf("=", pos);
			if (eq < 0) {
				throw new InvalidNameException("Invalid name: " + dn);
			}
			let type = dn.substring(pos, eq).trim();
			if (type.length === 0 || /[,;+]/.test(type)) {
				throw new InvalidNameException("Invalid name: " + dn);
			}
			if (type.toUpperCase().startsWith("OID.")) {
				type = type.substring(4);
			}
			if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(type) && !/^\d+(\.\d+)*$/.test(type)) {
				throw new InvalidNameException("Invalid name: " + dn);
			}
			pos = eq + 1;

			// attribute value
			while (pos < len && dn[pos] === " ") {
				pos++;
			}
			let value = "";
			if (dn[pos] === '"') {
				pos++;
				let closed = false;
				while (pos < len) {
					const c = dn[pos];
					if (c === "\\") {
						if (pos + 1 >= len) {
							throw new InvalidNameException("Invalid name: " + dn);
						}
						value += dn[pos + 1];
						pos += 2;
					} else if (c === '"') {
						closed = true;
						pos++;
						break;
					} else {
						value += c;
						pos++;
					}
				}
				if (!closed) {
					throw new InvalidNameException("Invalid name: " + dn);
				}
				while (pos < len && dn[pos] === " ") {
					pos++;
				}
				if (pos < len && ![",", ";", "+"].includes(dn[pos])) {
					throw new InvalidNameException("Invalid name: " + dn);
				}
			} else if (dn[pos] === "#") {
				const start = pos;
				pos++;
				while (pos < len && /[0-9A-Fa-f]/.test(dn[pos])) {
					pos++;
				}
				const hex = dn.substring(start + 1, pos);
				if (hex.length === 0 || hex.length % 2 !== 0) {
					throw new InvalidNameException("Invalid name: " + dn);
				}
				value = "#" + hex.toLowerCase();
				while (pos < len && dn[pos] === " ") {
					pos++;
				}
				if (pos < len && ![",", ";", "+"].includes(dn[pos])) {
					throw new InvalidNameException("Invalid name: " + dn);
				}
			} else {
				const bytes: number[] = [];
				let trailingSpaces = 0;
				while (pos < len && ![",", ";", "+"].includes(dn[pos])) {
					const c = dn[pos];
					if (c === "\\") {
						if (pos + 1 >= len) {
							throw new InvalidNameException("Invalid name: " + dn);
						}
						const next = dn[pos + 1];
						if (/[0-9A-Fa-f]/.test(next) && pos + 2 < len && /[0-9A-Fa-f]/.test(dn[pos + 2])) {
							bytes.push(parseInt(dn.substring(pos + 1, pos + 3), 16));
							pos += 3;
						} else if (',=+<>#;"\\ '.includes(next)) {
							bytes.push(...Buffer.from(next, "utf8"));
							pos += 2;
						} else {
							throw new InvalidNameException("Invalid name: " + dn);
						}
						trailingSpaces = 0;
					} else if (c === '"' || c === "<" || c === ">" || c === "=") {
						throw new InvalidNameException("Invalid name: " + dn);
					} else {
						bytes.push(...Buffer.from(c, "utf8"));
						trailingSpaces = c === " " ? trailingSpaces + 1 : 0;
						pos++;
					}
				}
				// unescaped trailing whitespace is not part of the value
				value = Buffer.from(bytes.slice(0, bytes.length - trailingSpaces)).toString("utf8");
			}

			entries.push(type.toLowerCase() + "=" + value.toUpperCase());

			if (pos < len && dn[pos] === "+") {
				pos++;
				continue;
			}
			break;
		}
		rdns.push({ entries: entries.toSorted() });

		if (pos < len && (dn[pos] === "," || dn[pos] === ";")) {
			pos++;
			continue;
		}
		break;
	}

	return rdns;
}

function rdnEquals(a: ParsedRdn, b: ParsedRdn): boolean {
	return a.entries.length === b.entries.length && a.entries.every((e, i) => e === b.entries[i]);
}

/** java.net.InetAddress comparison: the raw address bytes (an IPv4-mapped IPv6 address is an IPv4 address) */
function inetAddressBytes(address: string): number[] {
	// Guava InetAddresses.forString
	const version = isIP(address);
	if (version === 0) {
		throw new Error("'" + address + "' is not an IP string literal.");
	}
	if (version === 4) {
		return address.split(".").map((p) => parseInt(p, 10));
	}
	let text = address;
	const zone = text.indexOf("%");
	if (zone >= 0) {
		text = text.substring(0, zone);
	}
	// embedded IPv4 tail
	const lastColon = text.lastIndexOf(":");
	const tail = text.substring(lastColon + 1);
	if (tail.includes(".")) {
		const v4 = tail.split(".").map((p) => parseInt(p, 10));
		text =
			text.substring(0, lastColon + 1) +
			((v4[0] << 8) | v4[1]).toString(16) +
			":" +
			((v4[2] << 8) | v4[3]).toString(16);
	}
	const [head, rest] = text.split("::");
	const headGroups = head === "" ? [] : head.split(":");
	const restGroups = rest === undefined ? null : rest === "" ? [] : rest.split(":");
	let groups: string[];
	if (restGroups === null) {
		groups = headGroups;
	} else {
		groups = [
			...headGroups,
			...Array.from({ length: 8 - headGroups.length - restGroups.length }, () => "0"),
			...restGroups,
		];
	}
	const bytes: number[] = [];
	for (const g of groups) {
		const v = parseInt(g, 16);
		bytes.push((v >> 8) & 0xff, v & 0xff);
	}
	const isV4Mapped = bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
	return isV4Mapped ? bytes.slice(12) : bytes;
}

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
