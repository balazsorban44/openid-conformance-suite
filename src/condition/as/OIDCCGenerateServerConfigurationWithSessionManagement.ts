import type { JsonObject } from "../../framework/index.ts";
import { OIDCCGenerateServerConfiguration } from "./OIDCCGenerateServerConfiguration.ts";

export class OIDCCGenerateServerConfigurationWithSessionManagement extends OIDCCGenerateServerConfiguration {
	protected override addAdditionalConfiguration(server: JsonObject, baseUrl: string): void {
		server["check_session_iframe"] = baseUrl + "check_session_iframe";
		server["end_session_endpoint"] = baseUrl + "end_session_endpoint";
		server["frontchannel_logout_supported"] = true;
		server["frontchannel_logout_session_supported"] = true;
		server["backchannel_logout_supported"] = true;
		server["backchannel_logout_session_supported"] = true;
	}
}
