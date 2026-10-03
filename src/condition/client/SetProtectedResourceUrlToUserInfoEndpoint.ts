import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class SetProtectedResourceUrlToUserInfoEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	static override post: EnvironmentRequirements = { strings: ["protected_resource_url"] };

	override evaluate(env: Environment): Environment {
		const resourceUrl = env.getString("server", "userinfo_endpoint");

		if (!resourceUrl) {
			throw this.error(
				"userinfo_endpoint missing from server configuration. The user info is not a mandatory to implement feature in the OpenID Connect specification, but is mandatory for certification.",
			);
		}

		env.putString("protected_resource_url", resourceUrl);

		this.logSuccess(
			"userinfo_endpoint will be used to test access token. The user info is not a mandatory to implement feature in the OpenID Connect specification, but is mandatory for certification.",
			args("protected_resource_url", resourceUrl),
		);

		return env;
	}
}
