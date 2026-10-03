import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractExtractAccessToken } from "./AbstractExtractAccessToken.ts";

export class ExtractAccessTokenFromAuthorizationResponse extends AbstractExtractAccessToken {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_response"] };
	static override post: EnvironmentRequirements = { required: ["access_token"] };

	override evaluate(env: Environment): Environment {
		return this.extractAccessToken(env, "authorization_endpoint_response");
	}
}
