/**
 * What an RP test works with (the `rp` fixture in tests/fixtures.ts provides it): the emulated OP it starts, and
 * the client driver that makes the RP under test log in against it.
 *
 *   const op = await rp.start({ ...module options });   // the emulated OP is set up (upstream configure)
 *   const client = rp.driveClient();                    // GET client_driver.startUrl: the RP logs in against op.issuer
 *   await op.expect("authorization"); ...
 *   await client;                                       // the RP under test reports it finished
 *
 * The client driver contract is in targets/openid-client-rp/README.md: the start call blocks until the RP has run
 * its flow for the module (or gave up), so when it returns the RP will not send further requests.
 */
import { logModule } from "../suite/conditions.ts";
import type { ClientDriverConfig, TestConfig } from "../suite/config.ts";
import type { EventLog } from "../suite/log.ts";
import type { TestServer } from "../suite/server.ts";
import { startEmulatedOp, type EmulatedOp, type EmulatedOpOptions, type RpVariant } from "./op.ts";

export interface ClientDriverResult {
	status?: number;
	body?: unknown;
	error?: string;
}

export interface Rp {
	readonly testName: string;
	readonly variant: RpVariant;
	/** The test configuration for this module (`override` applied) */
	readonly config: TestConfig;
	/** How long the negative tests wait for requests the RP must not send (config waitTimeoutSeconds, default 5) */
	readonly waitTimeoutSeconds: number;
	/** The emulated OP (after start()) */
	readonly op: EmulatedOp;
	/** Sets up and serves the emulated OP with the module's options */
	start(options?: EmulatedOpOptions): Promise<EmulatedOp>;
	/** Makes the RP under test start its flow against the emulated OP; resolves when the RP reports it finished */
	driveClient(): Promise<ClientDriverResult>;
	/** Ends the test as skipped (upstream fireTestSkipped): logs "The test was skipped: <reason>" */
	skipTest(reason: string): never;
	/** Stops a client driver call that is still running */
	close(): Promise<void>;
}

export function createRp(ctx: {
	testName: string;
	variant: RpVariant;
	config: TestConfig;
	server: TestServer;
	log: EventLog;
	clientDriver: ClientDriverConfig | null;
	/** Playwright's testInfo.skip */
	skip: (reason: string) => never;
}): Rp {
	let op: EmulatedOp | null = null;
	let driving: Promise<ClientDriverResult> | null = null;
	const abort = new AbortController();
	const waitTimeoutSeconds =
		typeof ctx.config["waitTimeoutSeconds"] === "number" ? ctx.config["waitTimeoutSeconds"] : 5;
	return {
		testName: ctx.testName,
		variant: ctx.variant,
		config: ctx.config,
		waitTimeoutSeconds,
		get op() {
			if (op == null) {
				throw new Error("rp.start() has not been called");
			}
			return op;
		},
		async start(options = {}) {
			op = await startEmulatedOp(ctx.server, ctx, options);
			return op;
		},
		driveClient() {
			if (op == null) {
				throw new Error("rp.start() must be called before rp.driveClient()");
			}
			if (ctx.clientDriver == null) {
				throw new Error("The configuration has no client_driver to start the relying party under test");
			}
			const started = op;
			driving = driveClient(
				ctx.clientDriver,
				started.issuer,
				ctx.testName,
				ctx.variant,
				ctx.config,
				ctx.log,
				abort.signal,
			);
			return driving.finally(() => started.rpFinished());
		},
		skipTest(reason) {
			logModule({ result: "SKIPPED", msg: "The test was skipped: " + reason });
			return ctx.skip(reason);
		},
		async close() {
			abort.abort(new Error("The test has finished"));
			await driving;
		},
	};
}

/**
 * Kicks off the RP under test for one module: GET `client_driver.startUrl` with issuer, module, variant,
 * client_metadata_defaults, alias and the static client's credentials (see targets/openid-client-rp/README.md),
 * logged under TEST-RUNNER. Never throws: a failing driver call is logged as a WARNING.
 *
 * upstream: scripts/run-test-plan.py running the RP for a client test module
 */
export async function driveClient(
	driver: ClientDriverConfig,
	issuer: string,
	testName: string,
	variant: Record<string, string>,
	config: TestConfig,
	log: EventLog,
	signal?: AbortSignal,
): Promise<ClientDriverResult> {
	const url = new URL(driver.startUrl);
	const client = (config["client"] as Record<string, unknown> | undefined) ?? {};
	const params: Record<string, string> = {
		issuer: issuer.endsWith("/") ? issuer : issuer + "/",
		module: testName,
		variant: JSON.stringify(variant),
		client_metadata_defaults: JSON.stringify(config["client_metadata_defaults"] ?? {}),
	};
	if (typeof config["alias"] === "string") {
		params["alias"] = config["alias"];
	}
	for (const k of ["client_id", "client_secret", "jwks"]) {
		const v = client[k];
		if (v != null) {
			params[k] = typeof v === "string" ? v : JSON.stringify(v);
		}
	}
	for (const [k, v] of Object.entries({ ...params, ...driver.params })) {
		url.searchParams.set(k, v);
	}
	log.log("TEST-RUNNER", { msg: "Starting the relying party under test", url: url.toString(), result: "INFO" });
	try {
		const timeout = AbortSignal.timeout((driver.timeoutSeconds ?? 120) * 1000);
		const res = await fetch(url, { signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
		const text = await res.text();
		let body: unknown = text;
		try {
			body = JSON.parse(text);
		} catch {
			// not json
		}
		log.log("TEST-RUNNER", {
			msg: "Relying party under test finished",
			status: res.status,
			response: body,
			result: res.ok ? "INFO" : "WARNING",
		});
		return { status: res.status, body };
	} catch (e) {
		if (signal?.aborted) {
			// the test ended (passed or failed) while the RP was still running
			log.log("TEST-RUNNER", { msg: "Stopped waiting for the relying party under test", result: "INFO" });
			return { error: (e as Error).message };
		}
		log.log("TEST-RUNNER", {
			msg: "Relying party under test could not be driven: " + (e as Error).message,
			result: "WARNING",
		});
		return { error: (e as Error).message };
	}
}
