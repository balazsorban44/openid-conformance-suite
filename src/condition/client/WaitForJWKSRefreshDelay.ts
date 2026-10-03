import type { Environment } from "../../framework/index.ts";
import { AbstractWaitForSpecifiedSeconds } from "../common/AbstractWaitForSpecifiedSeconds.ts";

export class WaitForJWKSRefreshDelay extends AbstractWaitForSpecifiedSeconds {
	protected override getExpectedWaitSeconds(env: Environment): number {
		const defaultRefreshDelay = 60;
		const customRefreshDelay = env.getLong("config", "server.jwks_refresh_delay");

		if (customRefreshDelay == null) {
			return defaultRefreshDelay;
		}

		// The custom delay must be in the range 1..defaultRefreshDelay
		return Math.min(Math.max(1, customRefreshDelay), defaultRefreshDelay);
	}
}
