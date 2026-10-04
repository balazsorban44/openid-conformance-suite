import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
	BCP195_TLS_1_2_CIPHERS,
	fapiClientCiphers,
	ianaRecommendedCiphers,
	openSslCipherName,
	probeTls,
	tls12Ciphers,
	TLS_1_3_CIPHERS,
} from "./tls.ts";

const cert = readFileSync(new URL("../../configs/certs/localhost.crt", import.meta.url), "utf8");
const key = readFileSync(new URL("../../configs/certs/localhost.key", import.meta.url), "utf8");

/** An https server on a free port; `ciphers` restricts what it accepts (node:tls / OpenSSL defaults otherwise) */
async function listen(options: { ciphers?: string; minVersion?: "TLSv1.2" | "TLSv1.3" } = {}): Promise<{
	server: Server;
	port: number;
}> {
	const server = createServer({ cert, key, ...options }, (_req, res) => res.end("ok"));
	await new Promise<void>((resolve) => server.listen(0, "localhost", resolve));
	return { server, port: (server.address() as { port: number }).port };
}

describe("the IANA cipher suite names as OpenSSL names", () => {
	test("TLS 1.2 suites drop TLS_ and WITH, shorten the cipher and leave the RSA key exchange out", () => {
		expect(openSslCipherName("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")).toBe("ECDHE-RSA-AES128-GCM-SHA256");
		expect(openSslCipherName("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")).toBe("ECDHE-ECDSA-AES256-GCM-SHA384");
		expect(openSslCipherName("TLS_DHE_RSA_WITH_AES_128_CBC_SHA")).toBe("DHE-RSA-AES128-SHA");
		expect(openSslCipherName("TLS_RSA_WITH_AES_128_GCM_SHA256")).toBe("AES128-GCM-SHA256");
		expect(openSslCipherName("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")).toBe("ECDHE-RSA-CHACHA20-POLY1305");
		expect(openSslCipherName("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8")).toBe("ECDHE-ECDSA-AES128-CCM8");
	});

	test("TLS 1.3 suites keep their name", () => {
		expect(openSslCipherName("TLS_AES_128_GCM_SHA256")).toBe("TLS_AES_128_GCM_SHA256");
	});

	test("the recommended suites of tls-parameters-4.csv that OpenSSL implements", () => {
		const recommended = ianaRecommendedCiphers();
		expect(recommended).toEqual(
			expect.arrayContaining([
				"TLS_AES_128_GCM_SHA256",
				"TLS_CHACHA20_POLY1305_SHA256",
				"ECDHE-ECDSA-AES128-GCM-SHA256",
				"ECDHE-RSA-AES256-GCM-SHA384",
				"ECDHE-RSA-CHACHA20-POLY1305",
				"ECDHE-PSK-CHACHA20-POLY1305",
			]),
		);
		// not recommended (RSA key exchange, CBC)
		expect(recommended).not.toContain("AES128-GCM-SHA256");
		expect(recommended).not.toContain("ECDHE-RSA-AES128-SHA256");
		expect(recommended.some((c) => c.startsWith("DHE-"))).toBe(false);
	});

	test("the client's lists (FAPITLSClient)", () => {
		expect(tls12Ciphers(false)).toEqual([
			"DHE-RSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"DHE-RSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
		]);
		expect(tls12Ciphers(true).slice(0, 4)).toEqual(BCP195_TLS_1_2_CIPHERS);
		expect(fapiClientCiphers(true, true)).toEqual(
			expect.arrayContaining([...BCP195_TLS_1_2_CIPHERS, ...TLS_1_3_CIPHERS]),
		);
		expect(fapiClientCiphers(true, true)).not.toContain("DEFAULT");
		expect(fapiClientCiphers(false, false).at(-1)).toBe("DEFAULT");
	});
});

describe("probeTls against a local https server", () => {
	let defaults: { server: Server; port: number };
	let strict: { server: Server; port: number };
	beforeAll(async () => {
		defaults = await listen();
		strict = await listen({ ciphers: "ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256", minVersion: "TLSv1.2" });
	});
	afterAll(() => {
		defaults.server.close();
		strict.server.close();
	});

	test("reports the negotiated version and cipher (TLS 1.3 preferred over 1.2)", async () => {
		const result = await probeTls({
			host: "localhost",
			port: defaults.port,
			versions: ["TLSv1.2", "TLSv1.3"],
			ciphers: fapiClientCiphers(true, true),
		});
		expect(result).toMatchObject({ outcome: "connected", version: "TLSv1.3" });
		expect(result.outcome === "connected" && result.cipher.standardName).toMatch(/^TLS_/);
	});

	test("a TLS 1.2 only offer is answered with TLS 1.2 and an IANA name for the cipher", async () => {
		const result = await probeTls({
			host: "localhost",
			port: defaults.port,
			versions: ["TLSv1.2"],
			ciphers: ["AES128-GCM-SHA256"],
		});
		expect(result).toEqual({
			outcome: "connected",
			version: "TLSv1.2",
			cipher: { name: "AES128-GCM-SHA256", standardName: "TLS_RSA_WITH_AES_128_GCM_SHA256" },
		});
	});

	test("the server refusing TLS 1.0 / 1.1 is a protocol_version alert", async () => {
		for (const version of ["TLSv1.0", "TLSv1.1"] as const) {
			const result = await probeTls({ host: "localhost", port: defaults.port, versions: [version] });
			expect(result).toEqual({ outcome: "alert", description: "protocol_version" });
		}
	});

	test("a cipher the server does not accept is a handshake_failure alert", async () => {
		const result = await probeTls({
			host: "localhost",
			port: strict.port,
			versions: ["TLSv1.2"],
			ciphers: ["AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"],
		});
		expect(result).toEqual({ outcome: "alert", description: "handshake_failure" });
	});

	test("nothing listening is an error", async () => {
		const closed = await listen();
		await new Promise<void>((resolve) => closed.server.close(() => resolve()));
		const result = await probeTls({ host: "localhost", port: closed.port, versions: ["TLSv1.2", "TLSv1.3"] });
		expect(result.outcome).toBe("error");
	});
});
