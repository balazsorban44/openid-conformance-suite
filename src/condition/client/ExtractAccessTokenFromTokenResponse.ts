import type { Environment, EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractExtractAccessToken } from "./AbstractExtractAccessToken.ts";

export class ExtractAccessTokenFromTokenResponse extends AbstractExtractAccessToken {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_response"] };
	static override post: EnvironmentRequirements = { required: ["access_token"] };

	override evaluate(env: Environment): Environment {
		return this.extractAccessToken(env, "token_endpoint_response");
	}
}
