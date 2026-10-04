/**
 * Raw TLS handshakes for the TLS checks: connect to a host offering a range of protocol versions and a list of
 * cipher suites, and report what the server agreed to or how it refused (upstream util/FAPITLSClient, a
 * BouncyCastle client that aborts once the ServerHello is in; here the handshake completes and the socket is closed).
 *
 *   const result = await probeTls({ host, port, versions: ["TLSv1.2", "TLSv1.3"], ciphers: [...BCP195_TLS_1_2_CIPHERS, ...TLS_1_3_CIPHERS] });
 *   if (result.outcome === "connected") result.version, result.cipher.standardName ...
 *
 * The cipher lists are upstream's (FAPITLSClient), as OpenSSL names: the TLS 1.3 mandatory suites, the FAPI 1 /
 * RFC 7525 TLS 1.2 ciphers, the BCP 195 (RFC 9325) recommended TLS 1.2 ciphers and the suites IANA marks
 * recommended in tls-parameters-4.csv (bundled in data/, upstream's csv resource).
 */
import { readFileSync } from "node:fs";
import { connect, getCiphers } from "node:tls";

/** BouncyCastle ProtocolVersion names (upstream logs them as "TLSv1.2"; node:tls says "TLSv1" for 1.0) */
export type TlsVersion = "TLSv1.0" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export interface TlsProbe {
	host: string;
	port: number;
	/** The protocol versions offered (a contiguous range; BouncyCastle's getSupportedVersions) */
	versions: TlsVersion[];
	/**
	 * The cipher suites offered, as an OpenSSL cipher list (TLS 1.2 names, TLS 1.3 suite names and OpenSSL
	 * keywords such as DEFAULT); every cipher OpenSSL knows when left out
	 */
	ciphers?: string[];
}

export type TlsProbeResult =
	/** the handshake completed: the version and cipher the server chose */
	| { outcome: "connected"; version: TlsVersion; cipher: { name: string; standardName: string } }
	/** the server answered with a fatal alert (BouncyCastle TlsFatalAlertReceived) */
	| { outcome: "alert"; description: "handshake_failure" | "protocol_version" }
	/** the TCP connection was reset (Java SocketException "Connection reset") */
	| { outcome: "connection_reset" }
	/** the handshake failed on this side (BouncyCastle TlsFatalAlert) or the connection could not be made */
	| { outcome: "error"; error: Error; localHandshakeFailure: boolean };

const NODE_VERSION: Record<TlsVersion, "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3"> = {
	"TLSv1.0": "TLSv1",
	"TLSv1.1": "TLSv1.1",
	"TLSv1.2": "TLSv1.2",
	"TLSv1.3": "TLSv1.3",
};
const VERSION_ORDER: TlsVersion[] = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"];

/** The version node:tls reports, as BouncyCastle names it */
export function tlsVersionName(nodeName: string | null): TlsVersion | null {
	switch (nodeName) {
		case "TLSv1":
			return "TLSv1.0";
		case "TLSv1.1":
		case "TLSv1.2":
		case "TLSv1.3":
			return nodeName;
		default:
			return null;
	}
}

/** One TLS handshake with the server; the server certificate is not validated (upstream FAPITLSClient) */
export function probeTls(probe: TlsProbe): Promise<TlsProbeResult> {
	const offered = [...probe.versions].sort((a, b) => VERSION_ORDER.indexOf(a) - VERSION_ORDER.indexOf(b));
	const minVersion = NODE_VERSION[offered[0]];
	const maxVersion = NODE_VERSION[offered[offered.length - 1]];
	// SECLEVEL=0: OpenSSL otherwise refuses to offer TLS 1.0 / 1.1 and the weak ciphers the negative checks try
	const ciphers = [...(probe.ciphers ?? ["ALL", "COMPLEMENTOFALL"]), "@SECLEVEL=0"].join(":");
	return new Promise((resolve) => {
		let socket;
		try {
			socket = connect({
				host: probe.host,
				port: probe.port,
				servername: probe.host,
				rejectUnauthorized: false,
				minVersion,
				maxVersion,
				ciphers,
				timeout: 10_000,
			});
		} catch (e) {
			// OpenSSL refused the cipher list or the version range before connecting
			resolve(classify(e as NodeJS.ErrnoException));
			return;
		}
		let settled = false;
		const settle = (result: TlsProbeResult) => {
			if (!settled) {
				settled = true;
				resolve(result);
			}
			socket.destroy();
		};
		socket.once("secureConnect", () => {
			const cipher = socket.getCipher();
			settle({
				outcome: "connected",
				version: tlsVersionName(socket.getProtocol()) ?? "TLSv1.2",
				cipher: { name: cipher.name, standardName: cipher.standardName },
			});
		});
		socket.once("timeout", () =>
			settle({ outcome: "error", error: new Error("timed out"), localHandshakeFailure: false }),
		);
		socket.once("error", (error: NodeJS.ErrnoException) => settle(classify(error)));
	});
}

/** The TLS failure as upstream's conditions tell them apart */
function classify(error: NodeJS.ErrnoException): TlsProbeResult {
	const code = error.code ?? "";
	if (code.endsWith("ALERT_HANDSHAKE_FAILURE")) {
		return { outcome: "alert", description: "handshake_failure" };
	}
	if (code.endsWith("ALERT_PROTOCOL_VERSION")) {
		return { outcome: "alert", description: "protocol_version" };
	}
	if (code === "ECONNRESET") {
		return { outcome: "connection_reset" };
	}
	// OpenSSL gave up before any ServerHello (e.g. nothing to offer for the version range)
	const local = /NO_CIPHERS_AVAILABLE|NO_CIPHER_MATCH|NO_PROTOCOLS_AVAILABLE|UNSUPPORTED_PROTOCOL/.test(code);
	return { outcome: "error", error, localHandshakeFailure: local };
}

/** The TLS 1.3 mandatory-to-implement cipher suites (upstream FAPITLSClient.TLS_1_3_CIPHERS) */
export const TLS_1_3_CIPHERS = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"];

/** The ciphers permitted in FAPI specs for TLS 1.2 (which align with the older BCP195, RFC7525); FAPITLSClient.FAPI_TLS_1_2_CIPHERS */
export const FAPI_TLS_1_2_CIPHERS = [
	"DHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-GCM-SHA256",
	"DHE-RSA-AES256-GCM-SHA384",
	"ECDHE-RSA-AES256-GCM-SHA384",
];

/** The ciphers BCP195 (RFC9325 at the time of writing) recommends for TLS 1.2; FAPITLSClient.BCP195_TLS_1_2_CIPHERS */
export const BCP195_TLS_1_2_CIPHERS = [
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
];

/**
 * The OpenSSL name of an IANA cipher suite (RFC 8446 / TLS 1.2 naming): the TLS 1.3 suites keep their name, the
 * others drop the "TLS_" prefix and "WITH", shorten the cipher ("AES_128_GCM" -> "AES128-GCM", a CBC mode is
 * implied, CHACHA20_POLY1305 carries no MAC) and leave the RSA key exchange out.
 */
export function openSslCipherName(ianaName: string): string {
	const m = /^TLS_(.+)_WITH_(.+)$/.exec(ianaName);
	if (m == null) {
		return ianaName;
	}
	const keyExchange = m[1] === "RSA" ? "" : m[1].replaceAll("_", "-");
	const cipher = m[2]
		.replace(/CHACHA20_POLY1305_SHA256$/, "CHACHA20_POLY1305")
		.replace(/(AES|ARIA|CAMELLIA)_(128|256)/, "$1$2")
		.replace(/_CBC/, "")
		.replace(/CCM_8/, "CCM8")
		.replaceAll("_", "-");
	return keyExchange ? keyExchange + "-" + cipher : cipher;
}

let ianaRecommended: string[] | null = null;

/**
 * The cipher suites IANA marks "Recommended" in tls-parameters-4.csv that OpenSSL implements, as OpenSSL names
 * (upstream FAPITLSClient.getIANACiphers; the suites BouncyCastle does not know are left out there, the ones
 * OpenSSL does not know here).
 */
export function ianaRecommendedCiphers(): string[] {
	if (ianaRecommended != null) {
		return ianaRecommended;
	}
	const supported = new Set(getCiphers().map((name) => name.toUpperCase()));
	const ciphers: string[] = [];
	const csv = readFileSync(new URL("./data/tls-parameters-4.csv", import.meta.url), "utf8");
	for (let line of csv.split("\n")) {
		// Ignore fields that don't start with quoted values, eg. "0x00,0x02"
		if (!/^".*?".*/.test(line)) {
			continue;
		}
		// Remove the quoted value field.
		line = line.replace(/".*?",/, "");
		const fields = line.split(",");
		// Ignore entries that don't contain the required number of fields; accept only recommended, non-deprecated fields
		if (fields.length < 3 || fields[2] !== "Y") {
			continue;
		}
		const name = openSslCipherName(fields[0]);
		if (supported.has(name)) {
			ciphers.push(name);
		}
	}
	ianaRecommended = ciphers;
	return ciphers;
}

/** The TLS 1.2 ciphers the client offers (upstream FAPITLSClient.getTLS12Ciphers) */
export function tls12Ciphers(useBCP195Ciphers: boolean): string[] {
	if (useBCP195Ciphers) {
		// BCP195 TLS 1.2 recommended ciphers + non-deprecated ciphers from https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
		// as per https://bitbucket.org/openid/fapi/issues/847/52-network-layer-protections-are.
		return [...new Set([...BCP195_TLS_1_2_CIPHERS, ...ianaRecommendedCiphers()])];
	}
	return FAPI_TLS_1_2_CIPHERS;
}

/**
 * The cipher list of upstream's FAPITLSClient: the FAPI (or BCP195 + IANA) TLS 1.2 ciphers and the TLS 1.3 suites,
 * alone (`useOnlyFAPICiphers`) or followed by the client's defaults.
 */
export function fapiClientCiphers(useOnlyFAPICiphers: boolean, useBCP195Ciphers: boolean): string[] {
	const fapiCiphers = useBCP195Ciphers
		? [...new Set([...BCP195_TLS_1_2_CIPHERS, ...TLS_1_3_CIPHERS, ...ianaRecommendedCiphers()])]
		: [...new Set([...FAPI_TLS_1_2_CIPHERS, ...TLS_1_3_CIPHERS])];
	return useOnlyFAPICiphers ? fapiCiphers : [...fapiCiphers, "DEFAULT"];
}
