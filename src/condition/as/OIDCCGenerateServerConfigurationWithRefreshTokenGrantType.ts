import type { JsonArray, JsonObject } from "../../framework/index.ts";
import { OIDCCGenerateServerConfiguration } from "./OIDCCGenerateServerConfiguration.ts";

export class OIDCCGenerateServerConfigurationWithRefreshTokenGrantType extends OIDCCGenerateServerConfiguration {
	protected override addGrantTypes(server: JsonObject): void {
		super.addGrantTypes(server);
		const grantTypes = server["grant_types_supported"] as JsonArray;
		grantTypes.push("refresh_token");
	}
}
