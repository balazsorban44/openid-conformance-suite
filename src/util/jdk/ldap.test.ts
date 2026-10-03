import assert from "node:assert/strict";
import { test } from "vitest";
import { InvalidNameException, parseLdapName, rdnEquals } from "./ldap.ts";

// The comparison ValidateClientCertificateForTlsClientAuth performs: same number of RDNs, and every actual RDN
// is in the expected list (Java: expectedRDNs.contains(rdn)). Expected results were produced with
// javax.naming.ldap.LdapName / Rdn on OpenJDK 21.
function sameDn(expected: string, actual: string): boolean {
	const e = parseLdapName(expected);
	const a = parseLdapName(actual);
	return e.length === a.length && a.every((rdn) => e.some((x) => rdnEquals(x, rdn)));
}

test("parseLdapName: RDN order, case and escaping do not matter", () => {
	const equal: [string, string][] = [
		["CN=client,O=Example,C=US", "C=US,O=Example,CN=client"],
		["cn=Client, o=example", "CN=client,O=Example"],
		["CN=a\\,b,O=x", 'CN="a,b",O=x'],
		["CN=caf\\C3\\A9", "CN=café"],
		["CN=a+OU=b,O=x", "OU=b+CN=a,O=x"],
		["CN=a;O=b", "CN=a,O=b"],
		["CN=a  ", "CN=a"],
		["CN=  a", "CN=a"],
		["1.2.840.113549.1.9.1=#160d7465737440746573742e636f6d", "1.2.840.113549.1.9.1=#160D7465737440746573742E636F6D"],
		["", ""],
	];
	for (const [a, b] of equal) {
		assert.ok(sameDn(a, b), `${a} == ${b}`);
	}
});

test("parseLdapName: different names", () => {
	const different: [string, string][] = [
		["CN=client,O=Example", "CN=client,O=Other"],
		["CN=client,O=Example", "CN=client"],
		["CN=a+OU=b", "CN=a,OU=b"],
		// an escaped trailing space is part of the value
		["CN=a\\ ", "CN=a"],
		// attribute types are not mapped to OIDs
		["CN=x", "2.5.4.3=x"],
	];
	for (const [a, b] of different) {
		assert.ok(!sameDn(a, b), `${a} != ${b}`);
	}
});

test("parseLdapName: parsed RDN entries", () => {
	assert.deepEqual(parseLdapName("OU=QA+CN=client 1,O=Example\\, Inc.,C=US"), [
		{ entries: ["cn=CLIENT 1", "ou=QA"] },
		{ entries: ["o=EXAMPLE, INC."] },
		{ entries: ["c=US"] },
	]);
});

test("parseLdapName: InvalidNameException", () => {
	for (const dn of ["CN", "=x", "CN=a\\", 'CN="unterminated']) {
		assert.throws(
			() => parseLdapName(dn),
			(e: unknown) => e instanceof InvalidNameException && e.message === "Invalid name: " + dn,
			dn,
		);
	}
});
