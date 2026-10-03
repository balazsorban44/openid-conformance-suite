import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "vitest";
import {
	CertificateException,
	GeneralName,
	generateCertificates,
	getSubjectAlternativeNames,
	getSubjectX500PrincipalName,
	javaKeyAlgorithm,
} from "./x509.ts";

// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 36500
//   -subj "/C=US/O=Example, Inc./OU=QA+CN=client 1/emailAddress=a@b.c"
//   -addext "subjectAltName=DNS:client.example.com,URI:https://client.example.com/rp,IP:192.0.2.1,IP:2001:db8::1,email:client@example.com"
const PEM = `-----BEGIN CERTIFICATE-----
MIICdTCCAhugAwIBAgIUZk7K3s8COqWN/UuSLIqX18I0CMEwCgYIKoZIzj0EAwIw
WTELMAkGA1UEBhMCVVMxFjAUBgNVBAoMDUV4YW1wbGUsIEluYy4xHDAJBgNVBAsM
AlFBMA8GA1UEAwwIY2xpZW50IDExFDASBgkqhkiG9w0BCQEWBWFAYi5jMCAXDTI2
MTAwMzE1MTQxNVoYDzIxMjYwOTA5MTUxNDE1WjBZMQswCQYDVQQGEwJVUzEWMBQG
A1UECgwNRXhhbXBsZSwgSW5jLjEcMAkGA1UECwwCUUEwDwYDVQQDDAhjbGllbnQg
MTEUMBIGCSqGSIb3DQEJARYFYUBiLmMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQaAPeW5XtaYp6DMyBAdz0EUGGSJdNyx4qj1wnJopD9HW+N8Ku2zs07uEe8hX7H
UfbG4XlDTmD3qjsFmG/Cj4FEo4G+MIG7MB0GA1UdDgQWBBTmYcWYXkFHdolJKSuT
JKnm0E1mtjAfBgNVHSMEGDAWgBTmYcWYXkFHdolJKSuTJKnm0E1mtjAPBgNVHRMB
Af8EBTADAQH/MGgGA1UdEQRhMF+CEmNsaWVudC5leGFtcGxlLmNvbYYdaHR0cHM6
Ly9jbGllbnQuZXhhbXBsZS5jb20vcnCHBMAAAgGHECABDbgAAAAAAAAAAAAAAAGB
EmNsaWVudEBleGFtcGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiEAoXwRm0V+rcNx
QeDSl9XrXPvEzAW+TIC8EwxGRSPPA7wCICcwfLHca1+O7gBTWilLKx9+yYPeAEuw
BpM2e3bZUK/M
-----END CERTIFICATE-----
`;

// Expected values were produced with java.security.cert.X509Certificate on OpenJDK 21.

test("getSubjectX500PrincipalName: X500Principal.getName() (RFC 2253)", () => {
	assert.equal(
		getSubjectX500PrincipalName(new X509Certificate(PEM)),
		"1.2.840.113549.1.9.1=#16056140622e63,OU=QA+CN=client 1,O=Example\\, Inc.,C=US",
	);
});

test("getSubjectAlternativeNames", () => {
	assert.deepEqual(getSubjectAlternativeNames(new X509Certificate(PEM)), [
		[GeneralName.dNSName, "client.example.com"],
		[GeneralName.uniformResourceIdentifier, "https://client.example.com/rp"],
		[GeneralName.iPAddress, "192.0.2.1"],
		[GeneralName.iPAddress, "2001:db8:0:0:0:0:0:1"],
		[GeneralName.rfc822Name, "client@example.com"],
	]);
});

test("generateCertificates: concatenated DER, PEM, and errors", () => {
	const cert = new X509Certificate(PEM);
	const der = generateCertificates(Buffer.concat([cert.raw, cert.raw]));
	assert.equal(der.length, 2);
	assert.ok(der.every((c) => c.fingerprint256 === cert.fingerprint256));
	assert.equal(generateCertificates(Buffer.from(PEM + PEM)).length, 2);
	assert.throws(
		() => generateCertificates(Buffer.from([0x02, 0x01, 0x00])),
		(e: unknown) => e instanceof CertificateException && e.message === "Expected a DER SEQUENCE at offset 0",
	);
	assert.throws(
		() => generateCertificates(cert.raw.subarray(0, 100)),
		(e: unknown) => e instanceof CertificateException && e.message === "Truncated DER certificate at offset 0",
	);
});

test("javaKeyAlgorithm: PublicKey.getAlgorithm()", () => {
	assert.equal(javaKeyAlgorithm(new X509Certificate(PEM).publicKey), "EC");
});
