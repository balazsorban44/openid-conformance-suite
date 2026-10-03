import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreateInitiateLoginUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["initiate_login_uri"] };

	override evaluate(env: Environment): Environment {
		let baseUrl = env.getString("base_url") as string;

		if (baseUrl.length === 0) {
			throw this.error("Base URL is empty");
		}

		// Note that this url isn't actually ever called currently (we only pass it in the DCR request), but for consistency allow it to be overridden
		const externalUrlOverride = env.getString("external_url_override");
		if (externalUrlOverride) {
			baseUrl = externalUrlOverride;
		}

		// calculate the redirect URI based on our given base URL
		const initiateLoginUri = baseUrl + "/initiate_login";

		env.putString("initiate_login_uri", initiateLoginUri);

		this.logSuccess("Created initiate_login URI", args("initiate_login_uri", initiateLoginUri));

		return env;
	}
}
