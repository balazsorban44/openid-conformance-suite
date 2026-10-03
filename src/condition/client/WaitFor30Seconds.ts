import type { Environment } from "../../framework/index.ts";
import { AbstractWaitForSpecifiedSeconds } from "../common/AbstractWaitForSpecifiedSeconds.ts";

export class WaitFor30Seconds extends AbstractWaitForSpecifiedSeconds {
	protected override getExpectedWaitSeconds(_env: Environment): number {
		return 30;
	}
}
