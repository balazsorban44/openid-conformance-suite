import { RFC6749AppendixASyntaxUtils } from "./RFC6749AppendixASyntaxUtils.ts";

/**
 * Validates a single OAuth 2.0 scope-token against the RFC 6749 Appendix A.4 ABNF:
 * <pre>
 *   scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
 *   scope       = scope-token *( SP scope-token )
 * </pre>
 * i.e., one or more visible ASCII characters excluding SP (0x20), DQUOTE (0x22),
 * and BACKSLASH (0x5C). This class checks a single scope-token — callers that
 * accept space-separated lists must split on SP first.
 */
export class ScopeTokenSyntaxUtil {
	static isValidScopeToken(token: string | null | undefined): boolean {
		return ScopeTokenSyntaxUtil.scopeTokenSyntaxError(token) == null;
	}

	/**
	 * Returns a human-readable explanation of why {@code token} is not a valid RFC 6749
	 * Appendix A.4 scope-token (naming the offending character and its position), or
	 * {@code null} if {@code token} is a valid scope-token.
	 */
	static scopeTokenSyntaxError(token: string | null | undefined): string | null {
		if (token == null || token === "") {
			return "is empty; an RFC 6749 Appendix A.4 scope-token must contain at least one character";
		}
		for (let i = 0; i < token.length; i++) {
			const c = token.charCodeAt(i);
			if (!ScopeTokenSyntaxUtil.isValidScopeTokenChar(c)) {
				return (
					`contains ${ScopeTokenSyntaxUtil.describeChar(c)} at index ${i}, which is not permitted by the RFC 6749 Appendix A.4 ` +
					"scope-token ABNF (allowed characters are %x21, %x23-5B and %x5D-7E: visible ASCII " +
					"except space, double-quote and backslash)"
				);
			}
		}
		return null;
	}

	private static isValidScopeTokenChar(c: number): boolean {
		return RFC6749AppendixASyntaxUtils.isNQChar(c);
	}

	private static hex(c: number, width: number): string {
		return c.toString(16).toUpperCase().padStart(width, "0");
	}

	private static describeChar(c: number): string {
		switch (c) {
			case 0x20:
				return "' ' (0x20 SPACE)";
			case 0x22:
				return "'\"' (0x22 DQUOTE)";
			case 0x5c:
				return "'\\' (0x5C BACKSLASH)";
			default:
				if (c < 0x20 || c === 0x7f) {
					return `0x${ScopeTokenSyntaxUtil.hex(c, 2)} (control character)`;
				}
				if (c > 0x7e) {
					return `U+${ScopeTokenSyntaxUtil.hex(c, 4)} (non-ASCII character)`;
				}
				return `'${String.fromCharCode(c)}' (0x${ScopeTokenSyntaxUtil.hex(c, 2)})`;
		}
	}
}
