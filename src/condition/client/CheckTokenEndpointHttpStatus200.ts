import { AbstractCheckTokenEndpointHttpStatus } from "./AbstractCheckTokenEndpointHttpStatus.ts";

export class CheckTokenEndpointHttpStatus200 extends AbstractCheckTokenEndpointHttpStatus {
	protected override getExpectedHttpStatus(): number {
		return 200; // HttpStatus.OK
	}
}
