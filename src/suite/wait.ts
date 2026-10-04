/**
 * The waits upstream's tests take on purpose: the OP has to see time pass (a second between two logins so auth_time
 * differs, 30 seconds before an authorization code is used again). Never use these to wait for something to happen
 * (wait for the request or the page instead).
 */
import { condition } from "./conditions.ts";
import type { TestConfig } from "./config.ts";

/** upstream: condition/common/AbstractWaitForSpecifiedSeconds.java */
async function waitForSpecifiedSeconds(name: string, seconds: number): Promise<void> {
	const c = condition(name);
	c.success("Pausing for " + seconds + " seconds");
	await new Promise<void>((resolve) => setTimeout(resolve, seconds * 1000));
	c.success("Woke up after " + seconds + " seconds sleep");
}

/** upstream: condition/client/WaitForOneSecond.java */
export function waitForOneSecond(): Promise<void> {
	return waitForSpecifiedSeconds("WaitForOneSecond", 1);
}

/** upstream: condition/client/WaitFor2Seconds.java */
export function waitFor2Seconds(): Promise<void> {
	return waitForSpecifiedSeconds("WaitFor2Seconds", 2);
}

/**
 * The 30 seconds before an authorization code is used a second time (oidcc-codereuse-30seconds), shortened by
 * `server.code_reuse_delay` in the configuration (1..30; a suite-only property for implementations under test that
 * reject a reused code at once, like the bundled one).
 *
 * upstream: condition/client/WaitFor30Seconds.java
 */
export function waitFor30Seconds(config?: TestConfig): Promise<void> {
	return waitForSpecifiedSeconds("WaitFor30Seconds", configuredDelay(config, "code_reuse_delay", 30));
}

/** `server.<key>` of the configuration as a number of seconds, clamped to 1..`max`; `max` when absent */
function configuredDelay(config: TestConfig | undefined, key: string, max: number): number {
	const custom = (config?.server as Record<string, unknown> | undefined)?.[key];
	return typeof custom === "number" ? Math.min(Math.max(1, Math.trunc(custom)), max) : max;
}

/**
 * The wait before the OP is expected to fetch the client's rotated keys: 60 seconds, shortened by
 * `server.jwks_refresh_delay` in the configuration (1..60).
 *
 * upstream: condition/client/WaitForJWKSRefreshDelay.java
 */
export function waitForJWKSRefreshDelay(config: TestConfig): Promise<void> {
	return waitForSpecifiedSeconds("WaitForJWKSRefreshDelay", configuredDelay(config, "jwks_refresh_delay", 60));
}
