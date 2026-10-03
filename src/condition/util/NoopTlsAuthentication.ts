/**
 * Port of org.bouncycastle.tls.TlsAuthentication usage: accept any server certificate and never present a client
 * certificate. With node:tls the same effect is achieved with `rejectUnauthorized: false` and no cert/key, so this
 * class only carries the semantics.
 */
export class NoopTlsAuthentication {
	notifyServerCertificate(_serverCertificate: unknown): void {}

	getClientCredentials(_certificateRequest: unknown): null {
		return null;
	}
}
