import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractExtractRequestObject } from "./AbstractExtractRequestObject.ts";

export class ExtractRequestObject extends AbstractExtractRequestObject {
	static override pre: EnvironmentRequirements = {
		required: ["authorization_endpoint_http_request_params", "client", "server_jwks"],
	};
	static override post: EnvironmentRequirements = { required: ["authorization_request_object"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const requestObjectString = env.getString("authorization_endpoint_http_request_params", "request");
		await this.processRequestObjectString(requestObjectString, env);
		return env;
	}
}
