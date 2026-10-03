import type { JsonObject } from "../../framework/index.ts";
import { SetRequestParameterSupportedToTrueInServerConfiguration } from "./SetRequestParameterSupportedToTrueInServerConfiguration.ts";

export class SetRequestUriParameterSupportedToTrueInServerConfiguration extends SetRequestParameterSupportedToTrueInServerConfiguration {
	protected override addSupported(server: JsonObject): void {
		server["request_uri_parameter_supported"] = true;
		server["require_request_uri_registration"] = false;
	}

	protected override getLogMessage(): string {
		return "Enabled request_uri support in server configuration";
	}
}
