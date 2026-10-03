/** Emulation of `javax.naming.ldap.LdapName` / `Rdn` (RFC 2253 distinguished names). */

/**
 * The equivalent of javax.naming.ldap.Rdn for the purpose of comparing DNs: a set of attribute type/value pairs.
 * Types are compared case-insensitively and string values are compared by their unescaped, upper-cased value.
 */
export interface ParsedRdn {
	/** normalised "type=value" entries, sorted */
	entries: string[];
}

/** Port of `javax.naming.InvalidNameException` */
export class InvalidNameException extends Error {
	constructor(message: string) {
		super(message);
		this.name = "InvalidNameException";
	}
}

/**
 * Parses an RFC 2253 distinguished name (what javax.naming.ldap.LdapName does), throws InvalidNameException if
 * the name is not valid.
 */
export function parseLdapName(dn: string): ParsedRdn[] {
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

/** `javax.naming.ldap.Rdn.equals(Object)` */
export function rdnEquals(a: ParsedRdn, b: ParsedRdn): boolean {
	return a.entries.length === b.entries.length && a.entries.every((e, i) => e === b.entries[i]);
}
