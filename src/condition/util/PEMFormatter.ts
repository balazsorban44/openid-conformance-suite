export class PEMFormatter {
	private static readonly PEM_PATTERN = /^-----BEGIN [^-]+-----$(.*?)^-----END [^-]+-----$/dgms;

	static extractPEMHeader(input: string): string[] {
		const headerList: string[] = [];
		for (const m of input.matchAll(PEMFormatter.PEM_PATTERN)) {
			const indices = (m as RegExpMatchArray & { indices: [number, number][] }).indices;
			headerList.push(input.substring(m.index, indices[1]![0]));
		}

		return headerList;
	}

	/**
	 * Java's Base64.getDecoder(): strict basic alphabet, padding optional, throws IllegalArgumentException
	 * (here: Error) on illegal characters
	 */
	private static decodeBase64(input: string): Buffer {
		const stripped = input.replace(/={1,2}$/, "");
		if (!/^[A-Za-z0-9+/]*$/.test(stripped)) {
			throw new Error("Illegal base64 character in input");
		}
		if (stripped.length % 4 === 1) {
			throw new Error("Last unit does not have enough valid bits");
		}
		return Buffer.from(stripped, "base64");
	}

	/** @throws Error (Java: IllegalArgumentException) if the input is not valid base64 */
	static stripPEM(input: string): string {
		const matches = [...input.matchAll(PEMFormatter.PEM_PATTERN)];

		if (matches.length > 0) {
			// There may be multiple certificates, so concatenate and re-encode
			const out: Buffer[] = [];

			for (const m of matches) {
				const certStr = (m[1] as string).replace(/[\r\n]/g, "");
				out.push(PEMFormatter.decodeBase64(certStr));
			}

			return Buffer.concat(out).toString("base64");
		}

		// Assume it's a Base64-encoded DER format; check that it decodes OK
		PEMFormatter.decodeBase64(input);
		return input;
	}
}
