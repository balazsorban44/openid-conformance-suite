import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckRegistrationClientEndpointContentType extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["registration_client_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const contentType = env.getString("registration_client_endpoint_response", "headers.content-type");
		if (!contentType) {
			throw this.error("Couldn't find content-type header in registration_client_endpoint_response");
		}

		let mimeType: string | null = null;
		try {
			mimeType = contentType.split(";")[0].trim();
		} catch {
			// ignored
		}

		const expected = "application/json";
		if (expected !== mimeType) {
			throw this.error(
				"Invalid content-type header in registration_client_endpoint_response",
				args("expected", expected, "actual", contentType),
			);
		}

		this.logSuccess("registration_client_endpoint_response Content-Type: header is " + expected);
		return env;
	}
}
