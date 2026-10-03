import { AbstractEnsureHttpStatusCode } from "./AbstractEnsureHttpStatusCode.ts";

export class EnsureHttpStatusCodeIs201 extends AbstractEnsureHttpStatusCode {
	protected override getExpectedStatusCode(): number {
		return 201;
	}
}
