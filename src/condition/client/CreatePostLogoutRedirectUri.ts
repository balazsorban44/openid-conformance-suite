import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreatePostLogoutRedirectUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["post_logout_redirect_uri"] };

	override evaluate(env: Environment): Environment {
		const baseUrl = env.getString("base_url") as string;

		if (baseUrl.length === 0) {
			throw this.error("Base URL is empty");
		}

		const postLogoutRedirectUri = baseUrl + "/post_logout_redirect";

		env.putString("post_logout_redirect_uri", postLogoutRedirectUri);

		this.logSuccess("Created post_logout_redirect_uri URI", args("post_logout_redirect_uri", postLogoutRedirectUri));

		return env;
	}
}
