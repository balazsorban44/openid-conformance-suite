import { randomInt } from "node:crypto";

const ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALPHABETIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

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
	/** Random string from the given set of characters */
	next(length: number, chars: string): string {
		return fromAlphabet(chars, length);
	},
};
