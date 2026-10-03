import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractCheckForUnexpectedSchemaProperties } from "../AbstractCheckForUnexpectedSchemaProperties.ts";
import { JsonSchemaValidationInput } from "../../util/validation/JsonSchemaValidationInput.ts";

export class CheckForUnexpectedParametersInServerMetadata extends AbstractCheckForUnexpectedSchemaProperties {
	protected override createJsonSchemaValidationInput(env: Environment): JsonSchemaValidationInput {
		const serverMetadata = env.getObject("server");
		return new JsonSchemaValidationInput(
			"OAuth Authorization Server metadata",
			"json-schemas/rfc8414/oauth_authorization_server_metadata.json",
			serverMetadata,
		);
	}

	protected override getAllowUnexpectedFieldsConfigKey(): string | null {
		// Hidden escape hatch: a tester can add this JSON array of property names to the test
		// configuration to suppress warnings for extension metadata their authorization server
		// legitimately publishes.
		return "server.allow_unexpected_metadata_fields";
	}

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		return super.evaluate(env);
	}
}
