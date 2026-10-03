import { RFC6749AppendixASyntaxUtils } from "../../condition/util/RFC6749AppendixASyntaxUtils.ts";
import { isJsonArray, OIDFJSON, type JsonObject } from "../../framework/json.ts";

/**
 * The `DPoP-Nonce` response header supplied by an authorization or resource server, checked
 * against RFC 9449.
 *
 * <p>{@link DpopNonceResponseHeader.from} does not throw: the caller gets the nonce, a description of the way the
 * header breaks the RFC, or neither when the server did not send the header at all, so that the calling
 * condition is the one that raises the error and gets it attributed to itself.
 *
 * Java record: the components `nonce()` / `violation()` are the readonly fields `nonce` / `violation`.
 */
export class DpopNonceResponseHeader {
	/** Response headers are stored in the environment with lowercased names. */
	static readonly HEADER_NAME = "dpop-nonce";

	private static readonly ABSENT = new DpopNonceResponseHeader(null, null);

	readonly nonce: string | null;
	readonly violation: string | null;

	constructor(nonce: string | null, violation: string | null) {
		this.nonce = nonce;
		this.violation = violation;
	}

	/**
	 * @param responseHeaders the response headers as stored in the environment - lowercased names, with a
	 *                        header the server sent more than once stored as a JSON array
	 */
	static from(responseHeaders: JsonObject | null | undefined): DpopNonceResponseHeader {
		if (responseHeaders == null) {
			return DpopNonceResponseHeader.ABSENT;
		}

		const header = responseHeaders[DpopNonceResponseHeader.HEADER_NAME];
		if (header == null) {
			return DpopNonceResponseHeader.ABSENT;
		}

		if (isJsonArray(header)) {
			return DpopNonceResponseHeader.violation(
				"The response contains " +
					header.length +
					" DPoP-Nonce headers, but RFC9449 section 8 says there MUST NOT be more than one" +
					" DPoP-Nonce header.",
			);
		}

		if (!OIDFJSON.isString(header)) {
			return DpopNonceResponseHeader.violation("The DPoP-Nonce response header could not be read as a string.");
		}

		const value = OIDFJSON.getString(header);

		if (value.length === 0) {
			return DpopNonceResponseHeader.violation(
				"The DPoP-Nonce response header is empty, but RFC9449 section 8.1 defines" +
					" the nonce as '1*NQCHAR', which requires at least one character.",
			);
		}

		if (!RFC6749AppendixASyntaxUtils.isNQCharSequence(value)) {
			return DpopNonceResponseHeader.violation(
				"The DPoP-Nonce response header contains characters that are not allowed." +
					" RFC9449 section 8.1 defines the nonce as '1*NQCHAR', so only the characters" +
					" %x21 / %x23-5B / %x5D-7E may be used.",
			);
		}

		return new DpopNonceResponseHeader(value, null);
	}

	/**
	 * Wording for the log message of a condition that has just read a response, saying whether the server
	 * supplied a DPoP nonce on it.
	 *
	 * <p>This goes in the message, not in the logged details, for two reasons: it is then visible without
	 * expanding the entry, and it can live on an entry the condition logs on every call. A server is free to
	 * supply a nonce on one response and not the next, so an entry that appears only when a nonce arrives
	 * would make the number of log entries one condition call produces depend on what the server did, which
	 * the CI compare-results job reports as a difference between two otherwise identical runs. The nonce
	 * itself is not repeated here because the response headers are already logged with the response.
	 */
	static describeSuppliedNonce(suppliedNonce: string | null | undefined): string {
		return suppliedNonce == null ? "no DPoP nonce supplied" : "DPoP nonce supplied";
	}

	private static violation(description: string): DpopNonceResponseHeader {
		return new DpopNonceResponseHeader(null, description);
	}
}
