import { type Environment, type EnvironmentRequirements, type JsonObject } from "../../framework/index.ts";
import { AbstractJsonSchemaBasedValidation } from "../AbstractJsonSchemaBasedValidation.ts";
import { JsonSchemaValidationInput } from "../../util/validation/JsonSchemaValidationInput.ts";

/**
 * Validates the structure of authorization server / OpenID provider metadata (the `server`
 * environment object) against a superset JSON schema of RFC 8414 / OpenID Connect Discovery and the
 * various profile extensions. The schema is purely structural (types/formats of whatever fields are
 * present); only those errors are reported as failures. Unknown properties are ignored here and
 * instead surfaced as warnings by {@link CheckForUnexpectedParametersInServerMetadata}.
 * Required-field checks (including `issuer`) are left to the individual CheckDiscEndpoint* /
 * issuer-check conditions in each protocol's discovery verification.
 */
export class ValidateServerMetadataAgainstSchema extends AbstractJsonSchemaBasedValidation {
	protected override createJsonSchemaValidationInput(env: Environment): JsonSchemaValidationInput {
		const serverMetadata = this.getServerMetadata(env);
		const schemaResource = "json-schemas/rfc8414/oauth_authorization_server_metadata.json";
		const inputName = "OAuth Authorization Server metadata";
		return new JsonSchemaValidationInput(inputName, schemaResource, serverMetadata);
	}

	protected getServerMetadata(env: Environment): JsonObject | null {
		return env.getObject("server");
	}

	protected override ignoreUnknownPropertyStrictness(): boolean {
		return true;
	}

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return super.evaluate(env);
	}
}
