import {
	AbstractCondition,
	args,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class CreateBadRedirectUriByAppending extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["redirect_uri"] };

	override evaluate(env: Environment): Environment {
		const baseUrl = env.getString("base_url") as string;

		if (baseUrl === "") {
			throw this.error("Base URL is empty");
		}

		// create a random redirect URI, by appending a random path, which shouldn't be registered with the server
		const badRedirectPath = RandomStringUtils.nextAlphanumeric(10);
		const redirectUri = baseUrl + "/callback/" + badRedirectPath;
		env.putString("redirect_uri", redirectUri);
		env.putString("bad_redirect_path", badRedirectPath);

		this.logSuccess("Created a randomised (and hence unregistered) redirect URI", args("redirect_uri", redirectUri));

		return env;
	}
}
