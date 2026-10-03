import { AbstractEnsureHttpStatusCode } from "./AbstractEnsureHttpStatusCode.ts";

export class EnsureHttpStatusCodeIs200 extends AbstractEnsureHttpStatusCode {
	protected override getExpectedStatusCode(): number {
		return 200;
	}
}
