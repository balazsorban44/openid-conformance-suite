import type { JsonObject } from "../../framework/index.ts";

/**
 * Extracts the host and port of a given URL string (including the default port if none is
 * specified) into a JSON object, for use with TLS testing.
 */
export class TLSTestValueExtractor {
	private static readonly DEFAULT_PORTS: Record<string, number> = {
		"http:": 80,
		"https:": 443,
		"ftp:": 21,
	};

	static extractTlsFromUrl(urlString: string): JsonObject {
		const url = new URL(urlString);
		const tls: JsonObject = {};
		tls["testHost"] = url.hostname;
		const port = url.port !== "" ? Number(url.port) : (TLSTestValueExtractor.DEFAULT_PORTS[url.protocol] ?? -1);
		tls["testPort"] = port;

		return tls;
	}
}
