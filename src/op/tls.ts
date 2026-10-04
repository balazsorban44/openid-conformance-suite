/**
 * The TLS checks on an endpoint of the OP under test (upstream condition/common/*TLS*): the protocol versions it
 * agrees to, the ones it refuses and the cipher suites it accepts, each as its own handshake (src/suite/tls.ts).
 *
 *   const tls = extractTLSTestValuesFromResourceConfiguration(resource.url);     // { testHost, testPort }
 *   await checkEndpointTls(tls, state, { ...the checks the block runs });        // the FAPI 2 blocks
 */
import { condition, skipped, soft, type Condition } from "../suite/conditions.ts";
import { fapiClientCiphers, probeTls, tls12Ciphers, type TlsProbeResult, type TlsVersion } from "../suite/tls.ts";

/** The host and port of an endpoint under test (upstream env "tls", "<endpoint>_tls": TLSTestValueExtractor) */
export interface TlsTestValues {
	testHost: string;
	testPort: number;
}

/** upstream: condition/util/TLSTestValueExtractor.java (java.net.URL: the default port of the scheme when none is given) */
export function extractTlsFromUrl(url: string): TlsTestValues {
	const u = new URL(url);
	const defaults: Record<string, number> = { "http:": 80, "https:": 443, "ftp:": 21 };
	return { testHost: u.hostname, testPort: u.port !== "" ? Number(u.port) : (defaults[u.protocol] ?? -1) };
}

/** upstream: condition/client/ExtractTLSTestValuesFromResourceConfiguration.java */
export function extractTLSTestValuesFromResourceConfiguration(resourceUrl: string | null | undefined): TlsTestValues {
	const c: Condition = condition("ExtractTLSTestValuesFromResourceConfiguration");
	if (!resourceUrl) {
		c.failure("Resource endpoint not found");
	}
	let tls: TlsTestValues;
	try {
		tls = extractTlsFromUrl(resourceUrl);
	} catch (e) {
		if (e instanceof TypeError) {
			c.failureFrom("URL not properly formed", e);
		}
		throw e;
	}
	c.success("Extracted TLS information from resource endpoint", { resource_endpoint: tls });
	return tls;
}

/** What upstream's conditions keep between each other: "tls13_negotiated" (EnsureTLS13OrLater / EnsureTLS13PreferredOverTLS12) */
export interface TlsTestState {
	tls13Negotiated: boolean;
}

function hostAndPort(c: Condition, tls: TlsTestValues): { host: string; port: number } {
	if (!tls.testHost) {
		c.failure("Couldn't find host to connect for TLS");
	}
	if (tls.testPort == null) {
		c.failure("Couldn't find port to connect for TLS");
	}
	return { host: tls.testHost, port: tls.testPort };
}

/**
 * upstream: condition/common/EnsureTLS12OrLater.java (the connect of its subclasses): the versions offered, the
 * cipher list (FAPITLSClient), and what the server agreed to; `negotiated` is the subclass hook
 */
async function ensureTlsVersion(
	c: Condition,
	tls: TlsTestValues,
	allowed: TlsVersion[],
	ciphers: { useOnlyFAPICiphers: boolean; useBCP195Ciphers: boolean },
	negotiated: (serverVersion: TlsVersion) => void,
	successMessage: (serverVersion: TlsVersion) => string,
): Promise<void> {
	const { host, port } = hostAndPort(c, tls);
	const result = await probeTls({
		host,
		port,
		versions: allowed,
		ciphers: fapiClientCiphers(ciphers.useOnlyFAPICiphers, ciphers.useBCP195Ciphers),
	});
	if (result.outcome === "connected") {
		negotiated(result.version);
		if (allowed.includes(result.version)) {
			c.success(successMessage(result.version), { host, port });
			return;
		}
		c.failure("Server used incorrect TLS version", { server_version: result.version, host, port });
	}
	c.failureFrom("Failed to make TLS connection", probeError(result), { host, port });
}

/** The IOException upstream reports for a handshake that did not complete */
function probeError(result: Exclude<TlsProbeResult, { outcome: "connected" }>): Error {
	switch (result.outcome) {
		case "alert":
			return new Error("Received fatal alert " + result.description);
		case "connection_reset":
			return new Error("Connection reset");
		default:
			return result.error;
	}
}

/**
 * The server agrees to TLS 1.2 or 1.3 when offered only the BCP195 / IANA recommended ciphers.
 *
 * upstream: condition/common/EnsureTLS12RequireBCP195Ciphers.java (EnsureTLS12OrLater with FAPI + BCP195 ciphers)
 */
export async function ensureTLS12RequireBCP195Ciphers(tls: TlsTestValues, ...requirements: string[]): Promise<void> {
	const c: Condition = condition("EnsureTLS12RequireBCP195Ciphers", ...requirements);
	await ensureTlsVersion(
		c,
		tls,
		["TLSv1.2", "TLSv1.3"],
		{ useOnlyFAPICiphers: true, useBCP195Ciphers: true },
		() => {},
		() => "Server agreed to TLSv1.2 or TLSv1.3",
	);
}

/**
 * The server agrees to TLS 1.3 when only that is offered; records it for EnsureTLS13PreferredOverTLS12.
 *
 * upstream: condition/common/EnsureTLS13OrLater.java
 */
export async function ensureTLS13OrLater(
	tls: TlsTestValues,
	state: TlsTestState,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("EnsureTLS13OrLater", ...requirements);
	await ensureTlsVersion(
		c,
		tls,
		["TLSv1.3"],
		{ useOnlyFAPICiphers: false, useBCP195Ciphers: false },
		(serverVersion) => {
			state.tls13Negotiated = serverVersion === "TLSv1.3";
		},
		() => "Server agreed to TLSv1.3",
	);
}

/**
 * We know the server supports tls 1.3. Ensure it negotiates it over tls 1.2
 *
 * upstream: condition/common/EnsureTLS13PreferredOverTLS12.java
 */
export async function ensureTLS13PreferredOverTLS12(
	tls: TlsTestValues,
	state: TlsTestState,
	...requirements: string[]
): Promise<void> {
	const c: Condition = condition("EnsureTLS13PreferredOverTLS12", ...requirements);
	await ensureTlsVersion(
		c,
		tls,
		["TLSv1.3", "TLSv1.2"],
		{ useOnlyFAPICiphers: false, useBCP195Ciphers: false },
		(serverVersion) => {
			// Tidy up string set by EnsureTLS13OrLater that indicates tls 1.3 is supported.
			state.tls13Negotiated = false;
			if (serverVersion !== "TLSv1.3") {
				c.failure("Server negotiated TLS 1.2 when TLS 1.3 was available");
			}
		},
		(serverVersion) => "Server agreed to " + serverVersion,
	);
}

/** upstream: condition/common/AbstractDisallowTLSVersion.java */
async function disallowTlsVersion(
	name: string,
	disallowed: TlsVersion,
	protocolVersion: string,
	tls: TlsTestValues,
	requirements: string[],
): Promise<void> {
	const c: Condition = condition(name, ...requirements);
	const { host, port } = hostAndPort(c, tls);
	const result = await probeTls({
		host,
		port,
		versions: [disallowed],
		ciphers: fapiClientCiphers(false, false),
	});
	if (result.outcome === "connected") {
		if (result.version === disallowed) {
			c.failure(
				"The server accepted a " + protocolVersion + " connection. This is not permitted by the specification.",
				{ host, port },
			);
		}
		c.failure("Server used different TLS version than requested", { server_version: result.version, host, port });
	}
	if (
		result.outcome === "alert" ||
		(result.outcome === "error" && result.localHandshakeFailure) ||
		// AWS ELB seem to reject like this instead of by failing the handshake
		result.outcome === "connection_reset"
	) {
		// If we get here then we haven't received a server hello agreeing on a version
		c.success("Server refused " + protocolVersion + " handshake", { host, port });
		return;
	}
	c.failureFrom("Failed to make TLS connection, but in a different way than expected", result.error, { host, port });
}

/** upstream: condition/common/DisallowTLS10.java */
export function disallowTLS10(tls: TlsTestValues, ...requirements: string[]): Promise<void> {
	return disallowTlsVersion("DisallowTLS10", "TLSv1.0", "TLS 1.0", tls, requirements);
}

/** upstream: condition/common/DisallowTLS11.java */
export function disallowTLS11(tls: TlsTestValues, ...requirements: string[]): Promise<void> {
	return disallowTlsVersion("DisallowTLS11", "TLSv1.1", "TLS 1.1", tls, requirements);
}

/**
 * Connect with TLS 1.2 + the client's default cipher list to determine whether the server supports TLS 1.2 at
 * all (upstream AbstractCheckInsecureCiphers.probeTls12Supported)
 */
async function probeTls12Supported(c: Condition, host: string, port: number): Promise<boolean> {
	const result = await probeTls({ host, port, versions: ["TLSv1.2"], ciphers: ["DEFAULT"] });
	if (result.outcome === "connected") {
		return true;
	}
	if (
		result.outcome === "alert" ||
		(result.outcome === "error" && result.localHandshakeFailure) ||
		result.outcome === "connection_reset"
	) {
		return false;
	}
	return c.failureFrom("Failed to probe TLS 1.2 support", result.error, { host, port });
}

/**
 * upstream: condition/common/AbstractCheckInsecureCiphers.java: a TLS 1.2 handshake offering only `insecure`
 * ciphers (OpenSSL cipher list) must be refused; `cipherSuiteName` names the accepted one in upstream's terms
 */
async function checkInsecureCiphers(
	name: string,
	tls: TlsTestValues,
	insecure: string[],
	cipherSuiteName: (standardName: string) => string,
	requirements: string[],
): Promise<void> {
	const c: Condition = condition(name, ...requirements);
	const { host, port } = hostAndPort(c, tls);
	if (!(await probeTls12Supported(c, host, port))) {
		c.success("Server does not support TLS 1.2; insecure-cipher check is not applicable.", { host, port });
		return;
	}
	c.log(
		"Trying to connect with a non-permitted cipher (this is not exhaustive: check the server configuration manually to verify conformance)",
		{ host, port },
	);
	const result = await probeTls({ host, port, versions: ["TLSv1.2"], ciphers: insecure });
	if (result.outcome === "connected") {
		c.failure("Server accepted a cipher that is not on the list of permitted ciphers", {
			host,
			port,
			cipher_suite: cipherSuiteName(result.cipher.standardName),
		});
	}
	if (result.outcome === "alert" && result.description === "handshake_failure") {
		c.success("The TLS handshake was rejected when trying to connect with disallowed ciphers.", { host, port });
		return;
	}
	if (result.outcome === "error" && result.localHandshakeFailure) {
		c.success("The TLS handshake failed when trying to connect with disallowed ciphers.", { host, port });
		return;
	}
	if (result.outcome === "connection_reset") {
		c.success("The TCP connection was reset when trying to connect with disallowed ciphers.", { host, port });
		return;
	}
	c.failureFrom("Failed to make TLS connection, but in a different way than expected", probeError(result), {
		host,
		port,
	});
}

/**
 * A TLS 1.2 handshake offering every cipher but the BCP195 / IANA recommended ones must be refused.
 *
 * upstream: condition/common/RequireOnlyBCP195RecommendedCiphersForTLS12.java (DisallowInsecureCipher with BCP195
 * ciphers; the ciphers offered are all OpenSSL knows minus the allowed ones, where upstream offers all BouncyCastle
 * knows)
 */
export async function requireOnlyBCP195RecommendedCiphersForTLS12(
	tls: TlsTestValues,
	...requirements: string[]
): Promise<void> {
	// Obtain a list of allowed ciphers and remove them from the list of available ciphers (the TLS 1.3 suites among
	// them are no TLS 1.2 ciphers, and OpenSSL rejects a cipher list excluding them)
	const insecure = [
		"ALL",
		"COMPLEMENTOFALL",
		...tls12Ciphers(true)
			.filter((cipher) => !cipher.startsWith("TLS_"))
			.map((cipher) => "!" + cipher),
	];
	await checkInsecureCiphers(
		"RequireOnlyBCP195RecommendedCiphersForTLS12",
		tls,
		insecure,
		(standardName) => standardName,
		requirements,
	);
}

/**
 * Cipher suites that are not recommended in BCP195 are considered insecure for FAPI usage (a warning).
 *
 * upstream: condition/common/CheckForBCP195InsecureFAPICiphers.java
 */
export async function checkForBCP195InsecureFAPICiphers(tls: TlsTestValues, ...requirements: string[]): Promise<void> {
	// This map contains the cipher suites, which should produce a warning when detected.
	const insecure: Record<string, string> = {
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: "DHE_RSA_WITH_AES_128_GCM_SHA256",
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: "DHE_RSA_WITH_AES_256_GCM_SHA384",
	};
	await checkInsecureCiphers(
		"CheckForBCP195InsecureFAPICiphers",
		tls,
		["DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384"],
		(standardName) => insecure[standardName] ?? standardName,
		requirements,
	);
}

/** Which of the checks a FAPI 2 TLS block runs after the protocol version ones */
export interface EndpointTlsChecks {
	/** RequireOnlyBCP195RecommendedCiphersForTLS12 (not on the authorization endpoint: additional ciphers are allowed there) */
	requireOnlyBCP195Ciphers?: boolean;
	/** CheckForBCP195InsecureFAPICiphers (the token and resource endpoints) */
	checkInsecureFAPICiphers?: boolean;
}

/**
 * The TLS checks of a FAPI 2 endpoint block: EnsureTLS12RequireBCP195Ciphers, DisallowTLS10, DisallowTLS11,
 * EnsureTLS13OrLater (a warning), EnsureTLS13PreferredOverTLS12 (when TLS 1.3 was negotiated), and the cipher
 * checks the block includes. An endpoint the OP does not have (`tls` null) skips each check (upstream skipIfMissing
 * "tls").
 *
 * upstream: fapi2spfinal/FAPI2SPFinalHappyFlow.checkEndpointTLS and the blocks of
 * FAPI2SPFinalEnsureHolderOfKeyRequired.start
 */
export async function checkEndpointTls(
	tls: TlsTestValues | null,
	state: TlsTestState,
	checks: EndpointTlsChecks,
): Promise<void> {
	const versionRequirements = ["FAPI2-SP-FINAL-5.2.1-1", "FAPI2-SP-FINAL-5.2.1-2", "FAPI2-SP-FINAL-5.2.1-3"];
	if (tls == null) {
		skipped("EnsureTLS12RequireBCP195Ciphers", { object: "tls" }, "FAPI2-SP-FINAL-5.2.3-2", "FAPI-ISSUES-847");
		skipped("DisallowTLS10", { object: "tls" }, ...versionRequirements);
		skipped("DisallowTLS11", { object: "tls" }, ...versionRequirements);
		skipped("EnsureTLS13OrLater", { object: "tls" }, "RFC9325-3.1.1");
	} else {
		await soft(() => ensureTLS12RequireBCP195Ciphers(tls, "FAPI2-SP-FINAL-5.2.3-2", "FAPI-ISSUES-847"));
		await soft(() => disallowTLS10(tls, ...versionRequirements));
		await soft(() => disallowTLS11(tls, ...versionRequirements));
		await soft(() => ensureTLS13OrLater(tls, state, "RFC9325-3.1.1"), "warning");
	}
	if (state.tls13Negotiated && tls != null) {
		await soft(() => ensureTLS13PreferredOverTLS12(tls, state, "RFC9325-3.1.1"));
	} else {
		skipped("EnsureTLS13PreferredOverTLS12", { string: "tls13_negotiated" }, "RFC9325-3.1.1");
	}
	if (checks.requireOnlyBCP195Ciphers) {
		if (tls == null) {
			skipped(
				"RequireOnlyBCP195RecommendedCiphersForTLS12",
				{ object: "tls" },
				"FAPI2-SP-FINAL-5.2.2",
				"FAPI-ISSUES-847",
			);
		} else {
			await soft(() => requireOnlyBCP195RecommendedCiphersForTLS12(tls, "FAPI2-SP-FINAL-5.2.2", "FAPI-ISSUES-847"));
		}
	}
	if (checks.checkInsecureFAPICiphers && tls != null) {
		await soft(
			() => checkForBCP195InsecureFAPICiphers(tls, "FAPI2-SP-FINAL-5.2.2", "RFC9325A-A", "RFC9325-4.2"),
			"warning",
		);
	}
}
