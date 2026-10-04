import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { useTestLog } from "../suite/testing.ts";
import {
	checkEndpointTls,
	checkForBCP195InsecureFAPICiphers,
	disallowTLS10,
	disallowTLS11,
	ensureTLS12RequireBCP195Ciphers,
	ensureTLS13OrLater,
	ensureTLS13PreferredOverTLS12,
	extractTLSTestValuesFromResourceConfiguration,
	requireOnlyBCP195RecommendedCiphersForTLS12,
	type TlsTestValues,
} from "./tls.ts";

const t = useTestLog();
const cert = readFileSync(new URL("../../configs/certs/localhost.crt", import.meta.url), "utf8");
const key = readFileSync(new URL("../../configs/certs/localhost.key", import.meta.url), "utf8");

async function listen(options: { ciphers?: string; maxVersion?: "TLSv1.2" } = {}): Promise<{
	server: Server;
	tls: TlsTestValues;
}> {
	const server = createServer({ cert, key, ...options }, (_req, res) => res.end("ok"));
	await new Promise<void>((resolve) => server.listen(0, "localhost", resolve));
	return { server, tls: { testHost: "localhost", testPort: (server.address() as { port: number }).port } };
}

const BCP195_ONLY =
	"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";

describe("ExtractTLSTestValuesFromResourceConfiguration", () => {
	test("the host and port of the resource URL, the scheme's default port when none is given", () => {
		expect(extractTLSTestValuesFromResourceConfiguration("https://rs.example:8443/accounts")).toEqual({
			testHost: "rs.example",
			testPort: 8443,
		});
		expect(extractTLSTestValuesFromResourceConfiguration("https://rs.example/accounts")).toEqual({
			testHost: "rs.example",
			testPort: 443,
		});
		expect(t.entries().at(-1)).toMatchObject({
			src: "ExtractTLSTestValuesFromResourceConfiguration",
			result: "SUCCESS",
			resource_endpoint: { testHost: "rs.example", testPort: 443 },
		});
	});

	test("a missing or malformed URL", () => {
		expect(() => extractTLSTestValuesFromResourceConfiguration("")).toThrow("Resource endpoint not found");
		expect(() => extractTLSTestValuesFromResourceConfiguration("not a url")).toThrow("URL not properly formed");
	});
});

describe("the TLS checks against a local https server", () => {
	let compliant: { server: Server; tls: TlsTestValues };
	let lax: { server: Server; tls: TlsTestValues };
	let tls12Only: { server: Server; tls: TlsTestValues };
	beforeAll(async () => {
		compliant = await listen({ ciphers: BCP195_ONLY });
		lax = await listen();
		tls12Only = await listen({ ciphers: BCP195_ONLY, maxVersion: "TLSv1.2" });
	});
	afterAll(() => {
		compliant.server.close();
		lax.server.close();
		tls12Only.server.close();
	});

	test("EnsureTLS12RequireBCP195Ciphers: the server agrees to TLS 1.2 or 1.3 with the recommended ciphers", async () => {
		await ensureTLS12RequireBCP195Ciphers(compliant.tls, "FAPI2-SP-FINAL-5.2.3-2");
		expect(t.entries().at(-1)).toMatchObject({
			src: "EnsureTLS12RequireBCP195Ciphers",
			result: "SUCCESS",
			msg: "Server agreed to TLSv1.2 or TLSv1.3",
			host: "localhost",
			port: compliant.tls.testPort,
			requirements: ["FAPI2-SP-FINAL-5.2.3-2"],
		});
	});

	test("DisallowTLS10 / DisallowTLS11: a refused handshake is the success", async () => {
		await disallowTLS10(compliant.tls, "FAPI2-SP-FINAL-5.2.1-1");
		expect(t.entries().at(-1)).toMatchObject({
			src: "DisallowTLS10",
			result: "SUCCESS",
			msg: "Server refused TLS 1.0 handshake",
		});
		await disallowTLS11(compliant.tls, "FAPI2-SP-FINAL-5.2.1-1");
		expect(t.entries().at(-1)).toMatchObject({ src: "DisallowTLS11", msg: "Server refused TLS 1.1 handshake" });
	});

	test("EnsureTLS13OrLater records TLS 1.3 for EnsureTLS13PreferredOverTLS12", async () => {
		const state = { tls13Negotiated: false };
		await ensureTLS13OrLater(compliant.tls, state, "RFC9325-3.1.1");
		expect(state.tls13Negotiated).toBe(true);
		expect(t.entries().at(-1)).toMatchObject({ src: "EnsureTLS13OrLater", msg: "Server agreed to TLSv1.3" });
		await ensureTLS13PreferredOverTLS12(compliant.tls, state, "RFC9325-3.1.1");
		expect(state.tls13Negotiated).toBe(false);
		expect(t.entries().at(-1)).toMatchObject({ src: "EnsureTLS13PreferredOverTLS12", msg: "Server agreed to TLSv1.3" });
	});

	test("EnsureTLS13OrLater fails to connect to a TLS 1.2 only server", async () => {
		const state = { tls13Negotiated: false };
		await expect(ensureTLS13OrLater(tls12Only.tls, state)).rejects.toThrow("Failed to make TLS connection");
		expect(state.tls13Negotiated).toBe(false);
	});

	test("RequireOnlyBCP195RecommendedCiphersForTLS12: a server accepting another cipher fails, a strict one passes", async () => {
		await expect(requireOnlyBCP195RecommendedCiphersForTLS12(lax.tls, "FAPI2-SP-FINAL-5.2.2")).rejects.toThrow(
			"Server accepted a cipher that is not on the list of permitted ciphers",
		);
		expect(t.entries().at(-1)).toMatchObject({
			src: "RequireOnlyBCP195RecommendedCiphersForTLS12",
			result: "FAILURE",
			cipher_suite: expect.stringMatching(/^TLS_/),
		});
		await requireOnlyBCP195RecommendedCiphersForTLS12(compliant.tls, "FAPI2-SP-FINAL-5.2.2");
		expect(t.entries().at(-1)).toMatchObject({
			result: "SUCCESS",
			msg: "The TLS handshake was rejected when trying to connect with disallowed ciphers.",
		});
	});

	test("CheckForBCP195InsecureFAPICiphers: the DHE GCM ciphers are tried and must be refused", async () => {
		await checkForBCP195InsecureFAPICiphers(compliant.tls, "FAPI2-SP-FINAL-5.2.2");
		const entries = t.entries();
		expect(entries.at(-2)).toMatchObject({
			src: "CheckForBCP195InsecureFAPICiphers",
			msg: "Trying to connect with a non-permitted cipher (this is not exhaustive: check the server configuration manually to verify conformance)",
		});
		expect(entries.at(-1)).toMatchObject({ result: "SUCCESS" });
	});

	test("checkEndpointTls skips every check of an endpoint the OP does not have", async () => {
		const state = { tls13Negotiated: false };
		await checkEndpointTls(null, state, { requireOnlyBCP195Ciphers: true, checkInsecureFAPICiphers: true });
		expect(t.entries().map((e) => [e.src, e.msg])).toEqual([
			["EnsureTLS12RequireBCP195Ciphers", "Skipped evaluation due to missing required object: tls"],
			["DisallowTLS10", "Skipped evaluation due to missing required object: tls"],
			["DisallowTLS11", "Skipped evaluation due to missing required object: tls"],
			["EnsureTLS13OrLater", "Skipped evaluation due to missing required object: tls"],
			["EnsureTLS13PreferredOverTLS12", "Skipped evaluation due to missing required string: tls13_negotiated"],
			["RequireOnlyBCP195RecommendedCiphersForTLS12", "Skipped evaluation due to missing required object: tls"],
		]);
	});

	test("checkEndpointTls runs the block's checks in upstream's order", async () => {
		await checkEndpointTls(compliant.tls, { tls13Negotiated: false }, { requireOnlyBCP195Ciphers: true });
		expect([...new Set(t.entries().map((e) => e.src))]).toEqual([
			"EnsureTLS12RequireBCP195Ciphers",
			"DisallowTLS10",
			"DisallowTLS11",
			"EnsureTLS13OrLater",
			"EnsureTLS13PreferredOverTLS12",
			"RequireOnlyBCP195RecommendedCiphersForTLS12",
		]);
		expect(t.entries().filter((e) => e.result != null && e.result !== "SUCCESS")).toEqual([]);
	});
});
