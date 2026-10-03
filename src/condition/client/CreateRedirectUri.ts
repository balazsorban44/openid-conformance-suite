import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

/**
 * Creates a callback URL based on the base_url environment value
 */
export class CreateRedirectUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["redirect_uri"] };

	override evaluate(env: Environment): Environment {
		const baseUrl = env.getString("base_url") as string;

		if (baseUrl.length === 0) {
			throw this.error("Base URL is empty");
		}

		let suffix = env.getString("redirect_uri_suffix");
		if (suffix) {
			this.log("Appending suffix to redirect URI", args("suffix", suffix));
		} else {
			suffix = "";
		}

		// calculate the redirect URI based on our given base URL
		const redirectUri = baseUrl + "/callback" + suffix;

		env.putString("redirect_uri", redirectUri);

		this.logSuccess("Created redirect URI", args("redirect_uri", redirectUri));

		return env;
	}
}
