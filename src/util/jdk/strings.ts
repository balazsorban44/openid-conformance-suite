/** Emulation of `java.lang.String` / `java.util.Base64` / `java.net.URLEncoder` behaviour that differs from JS. */

/** Port of `java.lang.IllegalArgumentException` as thrown by `Base64.getDecoder().decode()`. */
export class IllegalArgumentException extends Error {
	constructor(message: string) {
		super(message);
		this.name = "IllegalArgumentException";
	}
}

/** Java String.getBytes(US_ASCII): every non-ASCII character (code point) becomes '?' */
export function toUsAscii(s: string): string {
	return Array.from(s, (c) => ((c.codePointAt(0) as number) > 0x7f ? "?" : c)).join("");
}

// Java String.isBlank(): true if the string is empty or contains only Character.isWhitespace code points
// (note this excludes the non-breaking spaces U+00A0, U+2007 and U+202F, which JS trim() would strip)
const JAVA_BLANK = new RegExp(
	// oxlint-disable-next-line no-control-regex
	"^[\\t\\n\\u000B\\f\\r\\u001C-\\u001F \\u1680\\u2000-\\u2006\\u2008-\\u200A\\u2028\\u2029\\u205F\\u3000]*$",
);

/** Java String.isBlank() */
export function isBlank(s: string): boolean {
	return JAVA_BLANK.test(s);
}

/** Equivalent of Java's URLEncoder.encode(s, UTF_8) (application/x-www-form-urlencoded) */
export function urlEncode(s: string): string {
	return new URLSearchParams([["x", s]]).toString().substring(2);
}

/**
 * `Base64.getDecoder().decode(s)`: the strict (basic, RFC 4648) decoder, which rejects characters outside the
 * base64 alphabet. Padding is optional.
 */
export function javaBase64Decode(s: string): Buffer {
	const m = /^([A-Za-z0-9+/]*)(={0,2})$/.exec(s);
	if (m == null) {
		const bad = [...s].find((c) => !/[A-Za-z0-9+/=]/.test(c));
		throw new IllegalArgumentException(
			bad != null
				? "Illegal base64 character " + bad.charCodeAt(0).toString(16)
				: "Input byte array has incorrect ending byte",
		);
	}
	const data = m[1];
	if (data.length % 4 === 1) {
		throw new IllegalArgumentException("Last unit does not have enough valid bits");
	}
	if (m[2].length > 0 && (data.length + m[2].length) % 4 !== 0) {
		throw new IllegalArgumentException("Input byte array has wrong 4-byte ending unit");
	}
	return Buffer.from(data, "base64");
}
