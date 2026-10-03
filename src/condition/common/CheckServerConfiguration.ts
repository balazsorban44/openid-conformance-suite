import { AbstractCheckServerConfiguration } from "./AbstractCheckServerConfiguration.ts";

export class CheckServerConfiguration extends AbstractCheckServerConfiguration {
	protected override getExpectedListEndpoint(): string[] {
		return ["authorization_endpoint", "token_endpoint", "issuer"];
	}
}
