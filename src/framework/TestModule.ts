import type { ModuleVariantMetadata } from "./variants.ts";

/** Port of testmodule/TestModule.java Status */
export const Status = {
	NOT_YET_CREATED: "NOT_YET_CREATED", // object just created, not yet setup
	CREATED: "CREATED", // test has been instantiated
	CONFIGURED: "CONFIGURED", // configuration files have been sent and set up
	RUNNING: "RUNNING", // test is executing
	WAITING: "WAITING", // test is waiting for external input
	INTERRUPTED: "INTERRUPTED", // test has been stopped before completion
	FINISHED: "FINISHED", // test has completed
} as const;
export type Status = (typeof Status)[keyof typeof Status];

/** Port of testmodule/TestModule.java Result */
export const Result = {
	PASSED: "PASSED", // test has passed successfully
	FAILED: "FAILED", // test has failed
	WARNING: "WARNING", // test has warnings
	REVIEW: "REVIEW", // test requires manual review
	SKIPPED: "SKIPPED", // test can not be completed
	UNKNOWN: "UNKNOWN", // test results not yet known, probably still running (see status)
} as const;
export type Result = (typeof Result)[keyof typeof Result];

/** Port of testmodule/PublishTestModule.java */
export interface PublishTestModule {
	testName: string;
	displayName: string;
	profile: string;
	configurationFields?: string[];
	summary?: string;
}

/**
 * A test module class. Every concrete module declares `static readonly meta: PublishTestModule` and, where the Java
 * class has variant annotations, `static override variants: ModuleVariantMetadata`.
 */
export interface TestModuleClass<T = unknown> {
	new (): T;
	readonly name: string;
	readonly meta?: PublishTestModule;
	readonly variants?: ModuleVariantMetadata;
}

/**
 * The parts of an incoming HTTP request handed to a test module alongside the parsed `requestParts`
 * (Java: HttpServletRequest). Mostly unused by modules; TLS details are used by the mTLS/TLS checks.
 */
export interface IncomingHttpRequest {
	method: string;
	url: string;
	headers: Record<string, string | string[] | undefined>;
	remoteAddress?: string;
	tls?: {
		cipher?: string;
		version?: string;
		clientCertificate?: string;
		clientCertificateChain?: string[];
	};
}

/** Java: HttpSession - a per-browser session store, keyed by a cookie set by the suite server */
export type HttpSession = Map<string, unknown>;
