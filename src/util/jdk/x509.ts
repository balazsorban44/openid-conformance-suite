/**
 * Emulation of the `java.security.cert` API surface the ported conditions use that node:crypto's X509Certificate
 * lacks: `CertificateFactory.generateCertificates`, `PublicKey.getAlgorithm()`,
 * `X509Certificate.getSubjectX500Principal().getName()` and `X509Certificate.getSubjectAlternativeNames()`.
 */
import { X509Certificate, type KeyObject } from "node:crypto";

/** Port of `java.security.cert.CertificateException` */
export class CertificateException extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "CertificateException";
	}
}

/**
 * `CertificateFactory.generateCertificates(stream)`: parses a sequence of DER encoded certificates (or PEM
 * blocks).
 *
 * @throws CertificateException
 */
export function generateCertificates(bytes: Buffer): X509Certificate[] {
	const certs: X509Certificate[] = [];
	try {
		const text = bytes.toString("latin1");
		if (text.includes("-----BEGIN CERTIFICATE-----")) {
			const pems = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
			for (const pem of pems) {
				certs.push(new X509Certificate(pem));
			}
			return certs;
		}
		let offset = 0;
		while (offset < bytes.length) {
			if (bytes[offset] !== 0x30) {
				throw new Error("Expected a DER SEQUENCE at offset " + offset);
			}
			let lengthByte = bytes[offset + 1];
			let headerLength = 2;
			let length = lengthByte;
			if (lengthByte & 0x80) {
				const n = lengthByte & 0x7f;
				length = 0;
				for (let i = 0; i < n; i++) {
					lengthByte = bytes[offset + 2 + i];
					length = length * 256 + lengthByte;
				}
				headerLength += n;
			}
			const end = offset + headerLength + length;
			if (end > bytes.length) {
				throw new Error("Truncated DER certificate at offset " + offset);
			}
			certs.push(new X509Certificate(bytes.subarray(offset, end)));
			offset = end;
		}
	} catch (e) {
		throw new CertificateException((e as Error).message, { cause: e });
	}
	return certs;
}

/** `PublicKey.getAlgorithm()` (BouncyCastle provider names) for a node:crypto key */
export function javaKeyAlgorithm(key: KeyObject): string {
	switch (key.asymmetricKeyType) {
		case "rsa":
			return "RSA";
		case "ec":
			return "EC";
		case "ed25519":
			return "Ed25519";
		default:
			return String(key.asymmetricKeyType);
	}
}

// Minimal DER reader: java.security.cert.X509Certificate exposes the subject (RFC 2253 name) and the
// subject alternative names directly, node:crypto's X509Certificate only exposes OpenSSL's text forms, so
// the two values the Java code uses are read straight from the DER encoding of the certificate.
interface DerElement {
	tag: number;
	start: number;
	contentStart: number;
	contentEnd: number;
	end: number;
}

function readDer(buf: Uint8Array, offset: number): DerElement {
	const tag = buf[offset];
	let pos = offset + 1;
	let length = buf[pos++];
	if (length & 0x80) {
		const n = length & 0x7f;
		length = 0;
		for (let i = 0; i < n; i++) {
			length = length * 256 + buf[pos++];
		}
	}
	if (pos + length > buf.length) {
		throw new Error("Invalid DER encoding: element exceeds the available data");
	}
	return { tag, start: offset, contentStart: pos, contentEnd: pos + length, end: pos + length };
}

function readDerChildren(buf: Uint8Array, el: DerElement): DerElement[] {
	const out: DerElement[] = [];
	let pos = el.contentStart;
	while (pos < el.contentEnd) {
		const child = readDer(buf, pos);
		out.push(child);
		pos = child.end;
	}
	return out;
}

function derOid(buf: Uint8Array, el: DerElement): string {
	const parts: number[] = [];
	let value = 0;
	for (let i = el.contentStart; i < el.contentEnd; i++) {
		value = value * 128 + (buf[i] & 0x7f);
		if (!(buf[i] & 0x80)) {
			if (parts.length === 0) {
				const first = Math.min(Math.floor(value / 40), 2);
				parts.push(first, value - first * 40);
			} else {
				parts.push(value);
			}
			value = 0;
		}
	}
	return parts.join(".");
}

// AVAKeyword entries that are RFC 2253 compliant in sun.security.x509
const RFC2253_KEYWORDS: Record<string, string> = {
	"2.5.4.3": "CN",
	"2.5.4.6": "C",
	"2.5.4.7": "L",
	"2.5.4.8": "ST",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.9": "STREET",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1": "UID",
};

function toHex(buf: Uint8Array, from: number, to: number): string {
	return Buffer.from(buf.subarray(from, to)).toString("hex");
}

function derStringValue(buf: Uint8Array, el: DerElement): string | null {
	const content = Buffer.from(buf.subarray(el.contentStart, el.contentEnd));
	switch (el.tag) {
		case 0x0c: // UTF8String
			return content.toString("utf8");
		case 0x13: // PrintableString
		case 0x16: // IA5String
		case 0x12: // NumericString
		case 0x1a: // VisibleString
			return content.toString("latin1");
		case 0x14: // TeletexString
			return content.toString("latin1");
		case 0x1e: // BMPString
			return Buffer.from(content).swap16().toString("utf16le");
		default:
			return null;
	}
}

function escapeRfc2253(value: string): string {
	let out = "";
	for (const c of value) {
		if (',+<>;"\\'.includes(c)) {
			out += "\\" + c;
		} else {
			out += c;
		}
	}
	if (out.startsWith("#") || out.startsWith(" ")) {
		out = "\\" + out;
	}
	if (out.endsWith(" ") && !out.endsWith("\\ ")) {
		out = out.substring(0, out.length - 1) + "\\ ";
	}
	return out;
}

/** The equivalent of X500Principal.getName() (RFC 2253 format) for a DER encoded Name */
function nameToRfc2253(buf: Uint8Array, name: DerElement): string {
	const rdns: string[] = [];
	for (const rdn of readDerChildren(buf, name)) {
		const avas: string[] = [];
		for (const ava of readDerChildren(buf, rdn)) {
			const [typeEl, valueEl] = readDerChildren(buf, ava);
			const oid = derOid(buf, typeEl);
			const keyword = RFC2253_KEYWORDS[oid];
			const str = keyword !== undefined ? derStringValue(buf, valueEl) : null;
			if (keyword !== undefined && str !== null) {
				avas.push(keyword + "=" + escapeRfc2253(str));
			} else {
				avas.push(oid + "=#" + toHex(buf, valueEl.start, valueEl.end));
			}
		}
		rdns.push(avas.join("+"));
	}
	// RFC 2253 lists the RDNs in reverse order
	return rdns.toReversed().join(",");
}

/** org.bouncycastle.asn1.x509.GeneralName tag numbers (as returned in getSubjectAlternativeNames()) */
export const GeneralName = {
	rfc822Name: 1,
	dNSName: 2,
	uniformResourceIdentifier: 6,
	iPAddress: 7,
} as const;

// GeneralName tags (context specific, implicit) in the subject alternative name extension
const SAN_RFC822_NAME = 0x81;
const SAN_DNS_NAME = 0x82;
const SAN_URI = 0x86;
const SAN_IP_ADDRESS = 0x87;

function ipToString(bytes: Buffer): string {
	if (bytes.length === 4) {
		return [...bytes].join(".");
	}
	const groups: string[] = [];
	for (let i = 0; i < bytes.length; i += 2) {
		groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
	}
	return groups.join(":");
}

const OID_SUBJECT_ALT_NAME = "2.5.29.17";

/** The TBSCertificate fields of a certificate and the index of the subject among them */
function tbsCertificate(der: Uint8Array): { tbsFields: DerElement[]; subjectIdx: number } {
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	const certificate = readDer(der, 0);
	const tbsFields = readDerChildren(der, readDer(der, certificate.contentStart));
	let idx = 0;
	if (tbsFields[idx].tag === 0xa0) {
		idx++; // explicit version
	}
	idx += 4; // serialNumber, signature, issuer, validity
	return { tbsFields, subjectIdx: idx };
}

/** `X509Certificate.getSubjectX500Principal().getName()` (RFC 2253 format) */
export function getSubjectX500PrincipalName(cert: X509Certificate): string {
	const der = new Uint8Array(cert.raw);
	const { tbsFields, subjectIdx } = tbsCertificate(der);
	return nameToRfc2253(der, tbsFields[subjectIdx]);
}

/**
 * `X509Certificate.getSubjectAlternativeNames()`: [GeneralName tag, value] pairs, limited to the string valued
 * rfc822Name, dNSName, uniformResourceIdentifier and iPAddress entries (an empty list when there is no extension;
 * Java returns null then).
 */
export function getSubjectAlternativeNames(cert: X509Certificate): [number, string][] {
	const der = new Uint8Array(cert.raw);
	const { tbsFields, subjectIdx } = tbsCertificate(der);
	const altNames: [number, string][] = [];

	// subjectPublicKeyInfo follows the subject; the optional extensions are in the [3] field after that
	for (const field of tbsFields.slice(subjectIdx + 2)) {
		if (field.tag !== 0xa3) {
			continue;
		}
		const extensions = readDerChildren(der, readDer(der, field.contentStart));
		for (const ext of extensions) {
			const parts = readDerChildren(der, ext);
			if (derOid(der, parts[0]) !== OID_SUBJECT_ALT_NAME) {
				continue;
			}
			const octets = parts[parts.length - 1];
			const generalNames = readDer(der, octets.contentStart);
			for (const altName of readDerChildren(der, generalNames)) {
				const content = Buffer.from(der.subarray(altName.contentStart, altName.contentEnd));
				switch (altName.tag) {
					case SAN_DNS_NAME:
						altNames.push([GeneralName.dNSName, content.toString("latin1")]);
						break;
					case SAN_IP_ADDRESS:
						altNames.push([GeneralName.iPAddress, ipToString(content)]);
						break;
					case SAN_URI:
						altNames.push([GeneralName.uniformResourceIdentifier, content.toString("latin1")]);
						break;
					case SAN_RFC822_NAME:
						altNames.push([GeneralName.rfc822Name, content.toString("latin1")]);
						break;
				}
			}
		}
	}
	return altNames;
}
