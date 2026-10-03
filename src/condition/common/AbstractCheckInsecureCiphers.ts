import { randomBytes } from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import {
	AbstractCondition,
	args,
	ConditionError,
	NamedError,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";
// Relied upon from the concurrently ported FAPITLSClient: `ProtocolVersion` with the BouncyCastle shape, i.e. an
// object exposing `getFullVersion(): number` (the wire version, e.g. TLSv12 -> 0x0303, TLSv10 -> 0x0301).
import type { ProtocolVersion } from "../../util/FAPITLSClient.ts";

// org.bouncycastle.tls.AlertDescription values used below
const ALERT_DESCRIPTION_HANDSHAKE_FAILURE = 40;
const ALERT_DESCRIPTION_PROTOCOL_VERSION = 70;
const ALERT_DESCRIPTION_ILLEGAL_PARAMETER = 47;

// How long we wait for the server to answer. (Upstream's blocking socket reads have no timeout.)
const PROBE_TIMEOUT_MS = 60_000;

/** Port of org.bouncycastle.tls.TlsFatalAlertReceived: the server sent us a fatal alert */
class TlsFatalAlertReceived extends NamedError {
	readonly alertDescription: number;

	constructor(alertDescription: number) {
		super("Internal TLS error, received fatal alert: " + alertDescription);
		this.alertDescription = alertDescription;
	}
}

/** Port of org.bouncycastle.tls.TlsFatalAlert: we aborted the handshake ourselves with the given alert */
class TlsFatalAlert extends NamedError {
	readonly alertDescription: number;

	constructor(alertDescription: number, message?: string) {
		super(message ?? "TLS fatal alert: " + alertDescription);
		this.alertDescription = alertDescription;
	}
}

interface ServerHello {
	version: number;
	cipherSuite: number;
}

function u16(n: number): Buffer {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(n);
	return b;
}

/**
 * Builds a TLS ClientHello that offers exactly the given cipher suites and the given protocol version.
 *
 * Java uses BouncyCastle's TlsClientProtocol with a DefaultTlsClient subclass that overrides getCipherSuites() /
 * getSupportedVersions() / getSNIServerNames(). OpenSSL (node:tls) cannot be told to offer arbitrary (insecure) IANA
 * cipher suites, and BC aborts the handshake as soon as the ServerHello is received (notifySelectedCipherSuite
 * throws), so the same is done here with a hand-built ClientHello and a parse of the server's first flight.
 */
function buildClientHello(host: string, cipherSuites: number[], fullVersion: number): Buffer {
	const extensions: Buffer[] = [];
	const ext = (type: number, data: Buffer) => extensions.push(Buffer.concat([u16(type), u16(data.length), data]));

	// server_name
	const name = Buffer.from(host, "utf8");
	const serverName = Buffer.concat([Buffer.from([0]), u16(name.length), name]);
	ext(0, Buffer.concat([u16(serverName.length), serverName]));
	// supported_groups: x25519, secp256r1, secp384r1, secp521r1, ffdhe2048, ffdhe3072, ffdhe4096
	const groups = Buffer.concat([29, 23, 24, 25, 256, 257, 258].map((g) => u16(g)));
	ext(10, Buffer.concat([u16(groups.length), groups]));
	// ec_point_formats: uncompressed
	ext(11, Buffer.from([1, 0]));
	// signature_algorithms
	const sigAlgs = Buffer.concat(
		[0x0601, 0x0501, 0x0401, 0x0201, 0x0603, 0x0503, 0x0403, 0x0203, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808].map((a) =>
			u16(a),
		),
	);
	ext(13, Buffer.concat([u16(sigAlgs.length), sigAlgs]));
	// extended_master_secret
	ext(23, Buffer.alloc(0));
	// renegotiation_info (empty)
	ext(0xff01, Buffer.from([0]));
	let clientVersion = fullVersion;
	if (fullVersion >= 0x0304) {
		// TLS 1.3 is negotiated using supported_versions
		clientVersion = 0x0303;
		ext(43, Buffer.concat([Buffer.from([2]), u16(fullVersion)]));
	}
	const extensionBytes = Buffer.concat(extensions);

	const suites = Buffer.concat(cipherSuites.map((c) => u16(c)));
	const body = Buffer.concat([
		u16(clientVersion),
		randomBytes(32),
		Buffer.from([0]), // empty session_id
		u16(suites.length),
		suites,
		Buffer.from([1, 0]), // null compression only
		u16(extensionBytes.length),
		extensionBytes,
	]);
	const handshake = Buffer.concat([
		Buffer.from([1]),
		Buffer.from([(body.length >> 16) & 0xff]),
		u16(body.length & 0xffff),
		body,
	]);
	return Buffer.concat([Buffer.from([0x16]), u16(0x0301), u16(handshake.length), handshake]);
}

/**
 * Sends the ClientHello and returns the ServerHello, or rejects with the equivalent of the exception BC would have
 * thrown (TlsFatalAlertReceived / TlsFatalAlert / a socket error such as ECONNRESET / a plain Error).
 */
function exchangeHello(socket: net.Socket, hello: Buffer): Promise<ServerHello> {
	return new Promise<ServerHello>((resolve, reject) => {
		let buffer = Buffer.alloc(0);
		let done = false;
		const finish = (fn: () => void) => {
			if (done) {
				return;
			}
			done = true;
			clearTimeout(timer);
			socket.removeAllListeners("data");
			fn();
		};
		const timer = setTimeout(
			() => finish(() => reject(new Error("Timed out waiting for the TLS server hello"))),
			PROBE_TIMEOUT_MS,
		);
		socket.on("data", (chunk: Buffer) => {
			buffer = Buffer.concat([buffer, chunk]);
			// process complete records
			while (buffer.length >= 5) {
				const type = buffer[0]!;
				const length = buffer.readUInt16BE(3);
				if (buffer.length < 5 + length) {
					return;
				}
				const payload = buffer.subarray(5, 5 + length);
				buffer = buffer.subarray(5 + length);
				if (type === 21) {
					// alert
					const level = payload[0];
					const description = payload[1] as number;
					if (level === 2) {
						finish(() => reject(new TlsFatalAlertReceived(description)));
						return;
					}
					continue; // warning alerts are ignored
				}
				if (type === 22) {
					// handshake
					if (payload[0] !== 2 || payload.length < 4 + 2 + 32 + 1) {
						finish(() => reject(new TlsFatalAlert(10, "Unexpected handshake message from server")));
						return;
					}
					const version = payload.readUInt16BE(4);
					const sessionIdLength = payload[4 + 2 + 32]!;
					const offset = 4 + 2 + 32 + 1 + sessionIdLength;
					if (payload.length < offset + 2) {
						finish(() => reject(new TlsFatalAlert(50, "Malformed server hello")));
						return;
					}
					const cipherSuite = payload.readUInt16BE(offset);
					finish(() => resolve({ version, cipherSuite }));
					return;
				}
				finish(() => reject(new TlsFatalAlert(10, "Unexpected TLS record type from server: " + type)));
				return;
			}
		});
		socket.once("error", (e) => finish(() => reject(e)));
		socket.once("close", () =>
			finish(() => reject(new Error("The server closed the connection without completing the handshake"))),
		);
		socket.write(hello);
	});
}

function isConnectionReset(e: unknown): boolean {
	return (e as NodeJS.ErrnoException | undefined)?.code === "ECONNRESET";
}

export abstract class AbstractCheckInsecureCiphers extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["tls"] };

	protected abstract getInsecureCiphers(): Map<number, string>;
	protected abstract getProtocolVersion(): ProtocolVersion;

	override async evaluate(env: Environment): Promise<Environment> {
		const tlsTestHost = env.getString("tls", "testHost");
		const tlsTestPort = env.getInteger("tls", "testPort");

		if (!tlsTestHost) {
			throw this.error("Couldn't find host to connect for TLS");
		}

		if (tlsTestPort == null) {
			throw this.error("Couldn't find port to connect for TLS");
		}

		if (!(await this.probeTls12Supported(tlsTestHost, tlsTestPort))) {
			this.logSuccess(
				"Server does not support TLS 1.2; insecure-cipher check is not applicable.",
				args("host", tlsTestHost, "port", tlsTestPort),
			);
			return env;
		}

		let socket: net.Socket | null = null;
		try {
			socket = await this.setupSocket(tlsTestHost, tlsTestPort);

			const insecureCiphers = this.getInsecureCiphers();
			const offeredCipherSuites = [...insecureCiphers.keys()];
			const protocolVersion = this.getProtocolVersion().getFullVersion();

			this.log(
				"Trying to connect with a non-permitted cipher (this is not exhaustive: check the server configuration manually to verify conformance)",
				args("host", tlsTestHost, "port", tlsTestPort),
			);

			const serverHello = await exchangeHello(
				socket,
				buildClientHello(tlsTestHost, offeredCipherSuites, protocolVersion),
			);

			// BC checks the version and the cipher suite chosen by the server before notifying the client
			if (serverHello.version !== protocolVersion && !(protocolVersion >= 0x0304 && serverHello.version === 0x0303)) {
				throw new TlsFatalAlert(ALERT_DESCRIPTION_PROTOCOL_VERSION);
			}
			if (!offeredCipherSuites.includes(serverHello.cipherSuite)) {
				throw new TlsFatalAlert(ALERT_DESCRIPTION_ILLEGAL_PARAMETER);
			}

			// notifySelectedCipherSuite
			throw this.error(
				"Server accepted a cipher that is not on the list of permitted ciphers",
				args("host", tlsTestHost, "port", tlsTestPort, "cipher_suite", insecureCiphers.get(serverHello.cipherSuite)),
			);
		} catch (e) {
			if (e instanceof ConditionError) {
				// It's our own error; pass it on
				throw e;
			} else if (e instanceof TlsFatalAlertReceived && e.alertDescription === ALERT_DESCRIPTION_HANDSHAKE_FAILURE) {
				this.logSuccess(
					"The TLS handshake was rejected when trying to connect with disallowed ciphers.",
					args("host", tlsTestHost, "port", tlsTestPort),
				);
				return env;
			} else if (e instanceof TlsFatalAlert && e.alertDescription === ALERT_DESCRIPTION_HANDSHAKE_FAILURE) {
				this.logSuccess(
					"The TLS handshake failed when trying to connect with disallowed ciphers.",
					args("host", tlsTestHost, "port", tlsTestPort),
				);
				return env;
			} else if (isConnectionReset(e)) {
				this.logSuccess(
					"The TCP connection was reset when trying to connect with disallowed ciphers.",
					args("host", tlsTestHost, "port", tlsTestPort),
				);
				return env;
			} else {
				throw this.error(
					"Failed to make TLS connection, but in a different way than expected",
					e,
					args("host", tlsTestHost, "port", tlsTestPort),
				);
			}
		} finally {
			// Don't care about errors on close
			socket?.destroy();
		}
	}

	/**
	 * Connect with TLS 1.2 + the default cipher list to determine whether the server
	 * supports TLS 1.2 at all. Returns true on a completed handshake; false when the
	 * server rejects the handshake at the TLS layer (protocol_version, handshake_failure,
	 * or TCP reset). Any other error is treated as an unexpected probe failure and
	 * surfaced via {@code throw error(...)} so it remains attributable.
	 *
	 * Java uses a BC DefaultTlsClient restricted to TLSv12; here node:tls restricted to TLS 1.2 is used. OpenSSL
	 * reports received alerts as error codes ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION / ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE.
	 */
	private async probeTls12Supported(host: string, port: number): Promise<boolean> {
		let socket: net.Socket | null = null;
		try {
			socket = await this.setupSocket(host, port);
			const connected = socket;
			await new Promise<void>((resolve, reject) => {
				const tlsSocket = tls.connect({
					socket: connected,
					servername: net.isIP(host) === 0 ? host : undefined,
					minVersion: "TLSv1.2",
					maxVersion: "TLSv1.2",
					rejectUnauthorized: false, // server certificate validation is deliberately skipped (NoopTlsAuthentication)
				});
				tlsSocket.setTimeout(PROBE_TIMEOUT_MS, () => tlsSocket.destroy(new Error("Timed out during TLS handshake")));
				tlsSocket.once("secureConnect", () => resolve());
				tlsSocket.once("error", reject);
			});
			return true;
		} catch (e) {
			const code = (e as NodeJS.ErrnoException | undefined)?.code;
			if (code === "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION" || code === "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE") {
				return false;
			}
			if (isConnectionReset(e)) {
				return false;
			}
			throw this.error("Failed to probe TLS 1.2 support", e, args("host", host, "port", port));
		} finally {
			socket?.destroy();
		}
	}

	/**
	 * @return a newly created socket
	 *
	 * UPSTREAM: AbstractCondition.setupSocket() in Java has a branch that creates the socket through the system HTTPS
	 * proxy (https.proxyHost / https.proxyPort / https.noProxy), but its condition is
	 * `Strings.isNullOrEmpty(proxyHost) && proxyPort != 0`, which can never connect to a configured proxy. This port
	 * has no such system properties and always connects directly.
	 */
	protected setupSocket(targetHost: string, targetPort: number): Promise<net.Socket> {
		return new Promise<net.Socket>((resolve, reject) => {
			const socket = net.connect({ host: targetHost, port: targetPort });
			socket.once("connect", () => {
				socket.removeListener("error", reject);
				resolve(socket);
			});
			socket.once("error", reject);
		});
	}
}
