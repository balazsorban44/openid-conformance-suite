import { AbstractCondition, type Environment } from "../../framework/index.ts";

export abstract class AbstractWaitForSpecifiedSeconds extends AbstractCondition {
	protected abstract getExpectedWaitSeconds(env: Environment): number;

	protected async sleepForSeconds(seconds: number): Promise<void> {
		await new Promise<void>((resolve) => setTimeout(resolve, seconds * 1000));
	}

	override async evaluate(env: Environment): Promise<Environment> {
		const expectedWaitSeconds = this.getExpectedWaitSeconds(env);

		this.logSuccess("Pausing for " + expectedWaitSeconds + " seconds");

		const lockManager = this.getLockManager();
		if (lockManager != null) {
			await lockManager.releaseLock();
		}
		try {
			await this.sleepForSeconds(expectedWaitSeconds);
		} finally {
			if (lockManager != null) {
				await lockManager.reacquireLock();
			}
		}

		this.logSuccess("Woke up after " + expectedWaitSeconds + " seconds sleep");
		return env;
	}
}
