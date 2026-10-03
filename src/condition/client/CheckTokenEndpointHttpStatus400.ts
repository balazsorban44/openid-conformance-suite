import { AbstractCheckTokenEndpointHttpStatus } from "./AbstractCheckTokenEndpointHttpStatus.ts";

export class CheckTokenEndpointHttpStatus400 extends AbstractCheckTokenEndpointHttpStatus {
	protected override getExpectedHttpStatus(): number {
		return 400; // HttpStatus.BAD_REQUEST
	}
}
