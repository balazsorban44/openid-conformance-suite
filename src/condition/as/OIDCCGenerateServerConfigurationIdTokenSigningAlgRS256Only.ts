import type { JsonArray, JsonObject } from "../../framework/index.ts";
import { OIDCCGenerateServerConfiguration } from "./OIDCCGenerateServerConfiguration.ts";

export class OIDCCGenerateServerConfigurationIdTokenSigningAlgRS256Only extends OIDCCGenerateServerConfiguration {
	protected override addIdTokenSigningAlgValuesSupported(server: JsonObject): void {
		const values: JsonArray = [];
		values.push("RS256");
		server["id_token_signing_alg_values_supported"] = values;
	}
}
