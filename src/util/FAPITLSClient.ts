import { readFileSync } from "node:fs";
import { isIP, Socket } from "node:net";
import { Duplex } from "node:stream";
import { connect as tlsConnect, type ConnectionOptions, type SecureVersion } from "node:tls";

// ---------------------------------------------------------------------------------------------------------------
// Ports of the BouncyCastle TLS types the probing conditions use (org.bouncycastle.tls.*).
// ---------------------------------------------------------------------------------------------------------------

/** Port of `org.bouncycastle.tls.ProtocolVersion` (the TLS/SSL versions node:tls can negotiate). */
export class ProtocolVersion {
	static readonly SSLv3 = new ProtocolVersion(0x0300, "SSL 3.0", null);
	static readonly TLSv10 = new ProtocolVersion(0x0301, "TLS 1.0", "TLSv1");
	static readonly TLSv11 = new ProtocolVersion(0x0302, "TLS 1.1", "TLSv1.1");
	static readonly TLSv12 = new ProtocolVersion(0x0303, "TLS 1.2", "TLSv1.2");
	static readonly TLSv13 = new ProtocolVersion(0x0304, "TLS 1.3", "TLSv1.3");

	readonly version: number;
	readonly name: string;
	/** The node:tls `minVersion`/`maxVersion` name, null when node cannot negotiate it. */
	readonly nodeName: SecureVersion | null;

	private constructor(version: number, name: string, nodeName: SecureVersion | null) {
		this.version = version;
		this.name = name;
		this.nodeName = nodeName;
	}

	static get(version: number): ProtocolVersion {
		for (const v of [
			ProtocolVersion.SSLv3,
			ProtocolVersion.TLSv10,
			ProtocolVersion.TLSv11,
			ProtocolVersion.TLSv12,
			ProtocolVersion.TLSv13,
		]) {
			if (v.version === version) {
				return v;
			}
		}
		const major = version >> 8;
		const minor = version & 0xff;
		return new ProtocolVersion(version, "UNKNOWN 0x" + ((major << 8) | minor).toString(16).padStart(4, "0"), null);
	}

	getName(): string {
		return this.name;
	}

	/** The wire version, e.g. 0x0303 for TLS 1.2. */
	getFullVersion(): number {
		return this.version;
	}

	getMajorVersion(): number {
		return this.version >> 8;
	}

	getMinorVersion(): number {
		return this.version & 0xff;
	}

	equals(other: unknown): boolean {
		return other instanceof ProtocolVersion && other.version === this.version;
	}

	toString(): string {
		return this.name;
	}
}

/** Port of the `org.bouncycastle.tls.AlertDescription` constants. */
export const AlertDescription = {
	close_notify: 0,
	unexpected_message: 10,
	bad_record_mac: 20,
	record_overflow: 22,
	handshake_failure: 40,
	bad_certificate: 42,
	unsupported_certificate: 43,
	certificate_revoked: 44,
	certificate_expired: 45,
	certificate_unknown: 46,
	illegal_parameter: 47,
	unknown_ca: 48,
	access_denied: 49,
	decode_error: 50,
	decrypt_error: 51,
	protocol_version: 70,
	insufficient_security: 71,
	internal_error: 80,
	inappropriate_fallback: 86,
	user_canceled: 90,
	no_renegotiation: 100,
	missing_extension: 109,
	unsupported_extension: 110,
	unrecognized_name: 112,
	bad_certificate_status_response: 113,
	unknown_psk_identity: 115,
	certificate_required: 116,
	no_application_protocol: 120,
} as const;

function alertName(description: number): string {
	for (const [name, value] of Object.entries(AlertDescription)) {
		if (value === description) {
			return name;
		}
	}
	return "UNKNOWN(" + description + ")";
}

/** Port of `java.io.IOException`: the base of the errors {@link DefaultTlsClient.connect} rejects with. */
export class IOException extends Error {
	constructor(message?: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "IOException";
	}
}

/** Port of `java.net.SocketException` (e.g. message "Connection reset"). */
export class SocketException extends IOException {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "SocketException";
	}
}

/** Port of `org.bouncycastle.tls.TlsFatalAlert`: a fatal alert raised locally (by the client). */
export class TlsFatalAlert extends IOException {
	readonly alertDescription: number;

	constructor(alertDescription: number, cause?: unknown) {
		super(alertName(alertDescription) + "(" + alertDescription + ")", cause === undefined ? undefined : { cause });
		this.name = "TlsFatalAlert";
		this.alertDescription = alertDescription;
	}

	getAlertDescription(): number {
		return this.alertDescription;
	}
}

/** Port of `org.bouncycastle.tls.TlsFatalAlertReceived`: a fatal alert sent by the server. */
export class TlsFatalAlertReceived extends IOException {
	readonly alertDescription: number;

	constructor(alertDescription: number) {
		super(alertName(alertDescription) + "(" + alertDescription + ")");
		this.name = "TlsFatalAlertReceived";
		this.alertDescription = alertDescription;
	}

	getAlertDescription(): number {
		return this.alertDescription;
	}
}

// ---------------------------------------------------------------------------------------------------------------
// Cipher suite tables
// ---------------------------------------------------------------------------------------------------------------

const DATA_DIR = new URL("./data/", import.meta.url);

/** IANA name -> { id, OpenSSL name } for every suite the OpenSSL in node can be asked to offer. */
const OPENSSL_CIPHER_SUITES = JSON.parse(
	readFileSync(new URL("openssl-cipher-suites.json", DATA_DIR), "utf8"),
) as Record<string, { id: number; openssl: string }>;

/** All single code point entries of the IANA TLS Cipher Suites registry: [id, name, recommended]. */
const IANA_REGISTRY: [number, string, string][] = (() => {
	const entries: [number, string, string][] = [];
	let text: string;
	try {
		text = readFileSync(new URL("tls-parameters-4.csv", DATA_DIR), "utf8");
	} catch {
		return entries;
	}
	for (const line of text.split(/\r?\n/)) {
		const m = /^"0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})",([^,]*),([^,]*),([^,]*)/.exec(line);
		if (m) {
			entries.push([(parseInt(m[1], 16) << 8) | parseInt(m[2], 16), m[3], m[5]]);
		}
	}
	return entries;
})();

const IANA_ID_BY_NAME = new Map<string, number>(IANA_REGISTRY.map(([id, name]) => [name, id]));

function cipherId(name: string): number {
	const id = IANA_ID_BY_NAME.get(name) ?? OPENSSL_CIPHER_SUITES[name]?.id;
	if (id == null) {
		throw new Error("Unknown cipher suite " + name);
	}
	return id;
}

/** id -> OpenSSL name, for building the node:tls `ciphers` string. */
const OPENSSL_NAME_BY_ID = new Map<number, string>(
	Object.values(OPENSSL_CIPHER_SUITES).map(({ id, openssl }) => [id, openssl]),
);

/**
 * Port of the `org.bouncycastle.tls.CipherSuite` constants as a name table: cipher suite id -> IANA name, for every
 * single code point entry in the IANA registry except the signalling cipher suite values (SCSV) and
 * unassigned/reserved code points. Replaces the reflection over BouncyCastle's CipherSuite class.
 */
export const CIPHER_SUITE_NAMES: ReadonlyMap<number, string> = new Map(
	IANA_REGISTRY.filter(
		([id, name]) =>
			id !== 0x00ff && id !== 0x5600 && name.startsWith("TLS_") && !name.includes("SCSV") && name !== "Unassigned",
	).map(([id, name]) => [id, name]),
);

/**
 * Port of the BouncyCastle `DefaultTlsClient` (org.bouncycastle.tls) as used by the TLS probing conditions, on top
 * of node:tls. Subclasses override the same hooks as in Java (`getCipherSuites`, `getSupportedVersions`,
 * `getSNIServerNames`, `notifyServerVersion`, `notifySelectedCipherSuite`).
 *
 * `new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream()).connect(client)` becomes
 * `await client.connect(host, port)`. The ServerHello is read off the wire before OpenSSL processes it, so
 * `notifyServerVersion` / `notifySelectedCipherSuite` are called at the same point of the handshake as in
 * BouncyCastle. The returned promise rejects with:
 * - whatever {@link IOException} a hook throws (e.g. `ServerHelloReceived`),
 * - a {@link TlsFatalAlert} wrapping (as `cause`) any other error a hook throws (BouncyCastle wraps
 *   RuntimeExceptions the same way, so `e.cause instanceof ConditionError` works as `e.getCause()` in Java),
 * - {@link TlsFatalAlertReceived} when the server sends a fatal alert,
 * - {@link SocketException} "Connection reset" when the server resets the connection,
 * - {@link TlsFatalAlert} (`internal_error`) when node/OpenSSL itself refuses to proceed (e.g. none of the
 *   requested cipher suites or protocol versions is available in this OpenSSL build),
 * - {@link IOException} for other network failures.
 *
 * Limitations: only cipher suites known to node's OpenSSL can be offered; others in `getCipherSuites()` are
 * silently left out of the ClientHello. When TLS 1.3 is enabled but `getCipherSuites()` contains no TLS 1.3 suite,
 * OpenSSL offers its default TLS 1.3 suites.
 */
export class DefaultTlsClient {
	/** Socket timeout in milliseconds for the whole probe. */
	timeoutMs = 10_000;

	/**
	 * The default cipher suites offered (BouncyCastle DefaultTlsClient's defaults).
	 */
	getCipherSuites(): number[] {
		return [
			"TLS_AES_256_GCM_SHA384",
			"TLS_AES_128_GCM_SHA256",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_CBC_SHA256",
			"TLS_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
		].map(cipherId);
	}

	protected getSupportedVersions(): ProtocolVersion[] {
		return [ProtocolVersion.TLSv13, ProtocolVersion.TLSv12];
	}

	/** Host names to send in the SNI extension (BouncyCastle `Vector<ServerName>`); null for none. */
	protected getSNIServerNames(): string[] | null {
		return null;
	}

	/** The server's certificate is never validated and no client certificate is sent (NoopTlsAuthentication). */
	getAuthentication(): {
		getClientCredentials(certificateRequest: unknown): null;
		notifyServerCertificate(serverCertificate: unknown): void;
	} {
		return {
			getClientCredentials: () => null,
			notifyServerCertificate: () => {},
		};
	}

	/** Called with the version the server selected in its ServerHello. */
	notifyServerVersion(_serverVersion: ProtocolVersion): void {}

	/** Called with the cipher suite the server selected in its ServerHello. */
	notifySelectedCipherSuite(_selectedCipherSuite: number): void {}

	/**
	 * Performs the TLS handshake with `host`:`port`, resolving when it completes and rejecting as described in the
	 * class documentation. Async (node:tls).
	 */
	connect(host: string, port: number): Promise<void> {
		const versions = this.getSupportedVersions().filter((v) => v.nodeName != null);
		const sorted = [...versions].sort((a, b) => a.version - b.version);
		const cipherNames = [...new Set(this.getCipherSuites())]
			.map((id) => OPENSSL_NAME_BY_ID.get(id))
			.filter((n): n is string => n != null);
		const tls13 = cipherNames.filter((n) => n.startsWith("TLS_"));
		const tls12 = cipherNames.filter((n) => !n.startsWith("TLS_"));
		const sni = this.getSNIServerNames()?.[0];

		return new Promise<void>((resolve, reject) => {
			let settled = false;
			let serverAlert: number | null = null;
			let serverHelloSeen = false;
			let buffer = Buffer.alloc(0);
			const raw = new Socket();
			let tlsSocket: ReturnType<typeof tlsConnect> | null = null;

			const finish = (err: unknown) => {
				if (settled) {
					return;
				}
				settled = true;
				tlsSocket?.destroy();
				raw.destroy();
				if (err == null) {
					resolve();
				} else {
					reject(err);
				}
			};

			const handleHookError = (e: unknown) => {
				finish(e instanceof IOException ? e : new TlsFatalAlert(AlertDescription.internal_error, e));
			};

			// Inspect the server's records until the ServerHello (or an alert) has been seen.
			const inspect = (chunk: Buffer) => {
				if (serverHelloSeen || serverAlert != null) {
					return;
				}
				buffer = Buffer.concat([buffer, chunk]);
				let offset = 0;
				let handshake = Buffer.alloc(0);
				while (buffer.length - offset >= 5) {
					const type = buffer[offset];
					const length = buffer.readUInt16BE(offset + 3);
					if (buffer.length - offset - 5 < length) {
						break;
					}
					const fragment = buffer.subarray(offset + 5, offset + 5 + length);
					offset += 5 + length;
					if (type === 21 && fragment.length >= 2) {
						if (fragment[0] === 2) {
							serverAlert = fragment[1];
						}
						return;
					}
					if (type !== 22) {
						return;
					}
					handshake = Buffer.concat([handshake, fragment]);
					if (handshake.length >= 4 && handshake[0] === 2) {
						const msgLength = handshake.readUIntBE(1, 3);
						if (handshake.length >= 4 + msgLength) {
							serverHelloSeen = true;
							const { version, cipherSuite } = parseServerHello(handshake.subarray(4, 4 + msgLength));
							try {
								this.notifyServerVersion(ProtocolVersion.get(version));
								this.notifySelectedCipherSuite(cipherSuite);
							} catch (e) {
								handleHookError(e);
							}
							return;
						}
					}
				}
			};

			// a duplex between OpenSSL and the TCP socket, so the server's bytes can be inspected first
			const proxy = new Duplex({
				read() {},
				write(chunk: Buffer, _encoding, callback) {
					raw.write(chunk, callback);
				},
				final(callback) {
					raw.end();
					callback();
				},
			});
			raw.on("data", (chunk: Buffer) => {
				inspect(chunk);
				if (!settled) {
					proxy.push(chunk);
				}
			});
			raw.on("end", () => proxy.push(null));
			raw.on("error", (e: NodeJS.ErrnoException) => {
				if (e.code === "ECONNRESET") {
					finish(new SocketException("Connection reset", { cause: e }));
				} else {
					finish(new IOException(e.message, { cause: e }));
				}
			});
			raw.setTimeout(this.timeoutMs, () => finish(new SocketException("Read timed out")));

			raw.connect(port, host, () => {
				const options: ConnectionOptions = {
					socket: proxy,
					rejectUnauthorized: false,
					// OpenSSL refuses an empty TLS 1.2 cipher list even when only TLS 1.3 is enabled; a TLS 1.2-only
					// suite is never offered in a TLS 1.3-only ClientHello, so a placeholder is harmless there
					ciphers:
						[...tls13, ...(tls12.length === 0 && sorted[0]?.nodeName === "TLSv1.3" ? ["NULL-SHA256"] : tls12)].join(
							":",
						) + ":@SECLEVEL=0",
					minVersion: sorted[0]?.nodeName ?? undefined,
					maxVersion: sorted[sorted.length - 1]?.nodeName ?? undefined,
				};
				if (sni != null && isIP(sni) === 0) {
					options.servername = sni;
				}
				try {
					tlsSocket = tlsConnect(options, () => finish(null));
				} catch (e) {
					finish(new TlsFatalAlert(AlertDescription.internal_error, e));
					return;
				}
				tlsSocket.on("error", (e: NodeJS.ErrnoException) => {
					if (serverAlert != null) {
						finish(new TlsFatalAlertReceived(serverAlert));
						return;
					}
					const received = /^ERR_SSL_(?:SSLV3|TLSV1|TLSV13)_ALERT_(.+)$/.exec(e.code ?? "");
					if (received) {
						const name = received[1].toLowerCase();
						const description = (AlertDescription as Record<string, number>)[name];
						finish(
							description != null ? new TlsFatalAlertReceived(description) : new IOException(e.message, { cause: e }),
						);
						return;
					}
					if (e.code === "ECONNRESET") {
						finish(new SocketException("Connection reset", { cause: e }));
						return;
					}
					finish(new TlsFatalAlert(AlertDescription.internal_error, e));
				});
				tlsSocket.on("close", () => {
					if (serverAlert != null) {
						finish(new TlsFatalAlertReceived(serverAlert));
					} else {
						finish(new IOException("No close_notify alert received before connection closed"));
					}
				});
			});
		});
	}
}

/** Reads the selected version (supported_versions extension for TLS 1.3) and cipher suite from a ServerHello body. */
function parseServerHello(body: Buffer): { version: number; cipherSuite: number } {
	let version = body.readUInt16BE(0);
	let offset = 2 + 32;
	const sessionIdLength = body[offset];
	offset += 1 + sessionIdLength;
	const cipherSuite = body.readUInt16BE(offset);
	offset += 2 + 1; // cipher suite, compression method
	if (offset + 2 <= body.length) {
		const extensionsEnd = offset + 2 + body.readUInt16BE(offset);
		offset += 2;
		while (offset + 4 <= extensionsEnd && offset + 4 <= body.length) {
			const type = body.readUInt16BE(offset);
			const length = body.readUInt16BE(offset + 2);
			if (type === 43 && length === 2) {
				version = body.readUInt16BE(offset + 4);
			}
			offset += 4 + length;
		}
	}
	return { version, cipherSuite };
}

// Signals that the connection was aborted after discovering the server version
export class ServerHelloReceived extends IOException {
	private readonly serverVersion: ProtocolVersion;

	constructor(serverVersion: ProtocolVersion) {
		super();
		this.name = "ServerHelloReceived";
		this.serverVersion = serverVersion;
	}

	getServerVersion(): ProtocolVersion {
		return this.serverVersion;
	}
}

export class FAPITLSClient extends DefaultTlsClient {
	/** Alias so `FAPITLSClient.ServerHelloReceived` works as in Java; the type is the exported {@link ServerHelloReceived}. */
	static readonly ServerHelloReceived = ServerHelloReceived;

	private readonly targetHost: string;
	private readonly allowOnlyFAPICiphers: boolean;
	private readonly useBCP195Ciphers: boolean = false;
	private readonly allowedProtocolVersion: ProtocolVersion[];

	// List of ciphers on mandatory to implement Cipher Suite of TLS 1.3
	private static readonly TLS_1_3_CIPHERS: readonly number[] = [
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_AES_128_GCM_SHA256",
	].map(cipherId);

	// List of ciphers permitted in FAPI specs for TLS 1.2 (which align with the older BCP195, RFC7525)
	private static readonly FAPI_TLS_1_2_CIPHERS: readonly number[] = [
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	].map(cipherId);

	// List of ciphers recommended in BCP195 spec for TLS 1.2 (at the time of writing, BCP195 refers to RFC9325)
	private static readonly BCP195_TLS_1_2_CIPHERS: readonly number[] = [
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	].map(cipherId);

	constructor(
		tlsTestHost: string,
		useOnlyFAPICiphers: boolean,
		useBCP195Ciphers: boolean,
		...protocolVersion: ProtocolVersion[]
	) {
		super();
		this.targetHost = tlsTestHost;
		this.allowOnlyFAPICiphers = useOnlyFAPICiphers;
		this.allowedProtocolVersion = protocolVersion;

		this.useBCP195Ciphers = useBCP195Ciphers;
	}

	// List of ciphers recommended in the IANA Transport Layer Security (TLS) Parameters document.
	private static IANA_TLS_1_2_CIPHERS: number[] | null = null;

	// Return an array of non-deprecated ciphers parsed from the 'tls-parameters-4.csv' resource file.
	private static getIANACiphers(): number[] {
		if (FAPITLSClient.IANA_TLS_1_2_CIPHERS != null) {
			// The IANA_TLS_1_2_CIPHERS array has already been populated from a static file.
			// No need to parse the file again.
			return FAPITLSClient.IANA_TLS_1_2_CIPHERS;
		}

		const ciphers: number[] = [];

		let text: string | null = null;
		try {
			text = readFileSync(new URL("tls-parameters-4.csv", DATA_DIR), "utf8");
		} catch {
			console.error("Failed to open the 'tls-parameters-4.csv' resource file. No IANA TLS ciphers returned.");
		}

		if (text != null) {
			for (let line of text.split(/\r?\n/)) {
				// Ignore fields that don't start with quoted values.
				// eg. "0x00,0x02"
				if (!/^".*?".*/.test(line)) {
					continue;
				}

				// Remove the quoted value field.
				line = line.replace(/".*?",/, "");

				// Java's String.split drops trailing empty strings
				const fields = line.split(",");
				while (fields.length > 0 && fields[fields.length - 1] === "") {
					fields.pop();
				}

				// Ignore entries that don't contain the required number of fields.
				if (fields.length < 3) {
					continue;
				}

				// Accept only recommended, non-deprecated fields
				if (fields[2] !== "Y") {
					continue;
				}

				// Add the CipherSuite value of the cipher to the result array.
				const id = IANA_ID_BY_NAME.get(fields[0]);
				if (id != null) {
					ciphers.push(id);
				}
				// else: CipherSuite does not contain this cipher. Ignore and carry on.
			}
		}

		FAPITLSClient.IANA_TLS_1_2_CIPHERS = ciphers;

		// Return the cipher array as an int[]
		return FAPITLSClient.IANA_TLS_1_2_CIPHERS;
	}

	static getTLS12Ciphers(useBCP195Ciphers: boolean): number[] {
		if (useBCP195Ciphers) {
			// BCP195 TLS 1.2 recommended ciphers + non-deprecated ciphers from https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
			// as per https://bitbucket.org/openid/fapi/issues/847/52-network-layer-protections-are.
			return [...new Set([...FAPITLSClient.BCP195_TLS_1_2_CIPHERS, ...FAPITLSClient.getIANACiphers()])];
		} else {
			return [...FAPITLSClient.FAPI_TLS_1_2_CIPHERS];
		}
	}

	override getCipherSuites(): number[] {
		let fapiCiphers: number[];

		// Construct the fapiCiphers list.
		if (this.useBCP195Ciphers) {
			// BCP195 TLS 1.2 recommended ciphers + TLS 1.3 mandatory ciphers.
			// Additionally the non-deprecated ciphers from https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
			// are included as per https://bitbucket.org/openid/fapi/issues/847/52-network-layer-protections-are.
			fapiCiphers = [
				...new Set([
					...FAPITLSClient.BCP195_TLS_1_2_CIPHERS,
					...FAPITLSClient.TLS_1_3_CIPHERS,
					...FAPITLSClient.getIANACiphers(),
				]),
			];
		} else {
			// FAPI TLS 1.2 ciphers + TLS 1.3 mandatory ciphers.
			fapiCiphers = [...new Set([...FAPITLSClient.FAPI_TLS_1_2_CIPHERS, ...FAPITLSClient.TLS_1_3_CIPHERS])];
		}

		if (this.allowOnlyFAPICiphers) {
			return fapiCiphers;
		} else {
			const defaultCiphers = super.getCipherSuites();
			return [...fapiCiphers, ...defaultCiphers];
		}
	}

	override getAuthentication(): {
		getClientCredentials(certificateRequest: unknown): null;
		notifyServerCertificate(serverCertificate: unknown): void;
	} {
		return {
			getClientCredentials: () => null,
			notifyServerCertificate: () => {
				// even though we make a TLS connection we ignore the server cert validation here
			},
		};
	}

	protected override getSupportedVersions(): ProtocolVersion[] {
		return this.allowedProtocolVersion;
	}

	protected override getSNIServerNames(): string[] {
		return [this.targetHost];
	}

	override notifyServerVersion(serverVersion: ProtocolVersion): void {
		// don't need to proceed further
		throw new ServerHelloReceived(serverVersion);
	}
}
