import { randomBytes, randomInt } from "node:crypto";

const ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALPHABETIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const NUMERIC = "0123456789";

function fromAlphabet(alphabet: string, length: number): string {
	let out = "";
	for (let i = 0; i < length; i++) {
		out += alphabet[randomInt(alphabet.length)];
	}
	return out;
}

/**
 * Port of the subset of Apache Commons RandomStringUtils.secure() used by upstream.
 */
export const RandomStringUtils = {
	nextAlphanumeric(length: number): string {
		return fromAlphabet(ALPHANUMERIC, length);
	},
	nextAlphabetic(length: number): string {
		return fromAlphabet(ALPHABETIC, length);
	},
	nextNumeric(length: number): string {
		return fromAlphabet(NUMERIC, length);
	},
	/** Random string from the given set of characters */
	next(length: number, chars: string): string {
		return fromAlphabet(chars, length);
	},
};

/** Random bytes as base64url, e.g. for nonces/states */
export function randomBase64Url(bytes: number): string {
	return randomBytes(bytes).toString("base64url");
}
