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

/** upstream: condition/client/WaitFor30Seconds.java */
export function waitFor30Seconds(): Promise<void> {
	return waitForSpecifiedSeconds("WaitFor30Seconds", 30);
}

/**
 * The wait before the OP is expected to fetch the client's rotated keys: 60 seconds, shortened by
 * `server.jwks_refresh_delay` in the configuration (1..60).
 *
 * upstream: condition/client/WaitForJWKSRefreshDelay.java
 */
export function waitForJWKSRefreshDelay(config: TestConfig): Promise<void> {
	const defaultRefreshDelay = 60;
	const custom = (config.server as Record<string, unknown> | undefined)?.["jwks_refresh_delay"];
	const seconds =
		typeof custom === "number" ? Math.min(Math.max(1, Math.trunc(custom)), defaultRefreshDelay) : defaultRefreshDelay;
	return waitForSpecifiedSeconds("WaitForJWKSRefreshDelay", seconds);
}
