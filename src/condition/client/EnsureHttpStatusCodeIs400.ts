import { AbstractEnsureHttpStatusCode } from "./AbstractEnsureHttpStatusCode.ts";

export class EnsureHttpStatusCodeIs400 extends AbstractEnsureHttpStatusCode {
	protected override getExpectedStatusCode(): number {
		return 400;
	}
}
