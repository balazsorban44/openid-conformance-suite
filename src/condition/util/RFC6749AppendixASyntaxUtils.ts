import { randomInt } from "node:crypto";

export class RFC6749AppendixASyntaxUtils {
	/**
	 * VSCHAR     = %x20-7E
	 * @return random VSCHAR String
	 */
	static generateVSChar(alphaCount: number, numberCount: number, punctuationCount: number): string {
		let puncts = "";
		if (punctuationCount > 0) {
			const pairs: [string, string][] = [
				[" ", "/"],
				[":", "@"],
				["[", "`"],
				["{", "~"],
			];
			puncts = RFC6749AppendixASyntaxUtils.generate(pairs, punctuationCount);
		}
		const numbers = RFC6749AppendixASyntaxUtils.generateNumberChar(numberCount);
		const alphas = RFC6749AppendixASyntaxUtils.generateAlphaChar(alphaCount);
		return alphas + numbers + puncts;
	}

	/**
	 * NQCHAR     = %x21 / %x23-5B / %x5D-7E
	 * @return random NQCHAR String
	 */
	static generateNQChar(alphaCount: number, numberCount: number, punctuationCount: number): string {
		let puncts = "";
		if (punctuationCount > 0) {
			const pairs: [string, string][] = [
				["!", "!"],
				["#", "/"],
				[":", "@"],
				["[", "["],
				["]", "`"],
				["{", "~"],
			];
			puncts = RFC6749AppendixASyntaxUtils.generate(pairs, punctuationCount);
		}
		const numbers = RFC6749AppendixASyntaxUtils.generateNumberChar(numberCount);
		const alphas = RFC6749AppendixASyntaxUtils.generateAlphaChar(alphaCount);
		return alphas + numbers + puncts;
	}

	/**
	 * NQCHAR     = %x21 / %x23-5B / %x5D-7E
	 * i.e. visible ASCII other than space, double-quote and backslash.
	 *
	 * @param c the UTF-16 code unit (Java: char)
	 */
	static isNQChar(c: number): boolean {
		return c === 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e);
	}

	/**
	 * Whether the value matches {@code 1*NQCHAR}, i.e. is non-empty and made up entirely of
	 * {@link #isNQChar(char) NQCHAR}. This is the syntax RFC 6749 Appendix A gives for a scope-token, and
	 * that RFC 9449 section 8.1 reuses for a DPoP nonce.
	 */
	static isNQCharSequence(value: string | null | undefined): boolean {
		if (value == null || value === "") {
			return false;
		}
		for (let i = 0; i < value.length; i++) {
			if (!RFC6749AppendixASyntaxUtils.isNQChar(value.charCodeAt(i))) {
				return false;
			}
		}
		return true;
	}

	private static generateAlphaChar(alphaCount: number): string {
		let alphas = "";
		if (alphaCount > 0) {
			const pairs: [string, string][] = [
				["a", "z"],
				["A", "Z"],
			];
			alphas = RFC6749AppendixASyntaxUtils.generate(pairs, alphaCount);
		}
		return alphas;
	}

	private static generateNumberChar(numberCount: number): string {
		let numbers = "";
		if (numberCount > 0) {
			numbers = RFC6749AppendixASyntaxUtils.generate([["0", "9"]], numberCount); //0 to 9
		}
		return numbers;
	}

	/** Equivalent of new RandomStringGenerator.Builder().withinRange(pairs).get().generate(count) */
	private static generate(pairs: [string, string][], count: number): string {
		const chars: string[] = [];
		for (const [from, to] of pairs) {
			for (let c = from.charCodeAt(0); c <= to.charCodeAt(0); c++) {
				chars.push(String.fromCharCode(c));
			}
		}
		let out = "";
		for (let i = 0; i < count; i++) {
			out += chars[randomInt(chars.length)];
		}
		return out;
	}
}
