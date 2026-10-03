import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export abstract class AbstractVerifyUserInfoAndIdTokenSameSub extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["userinfo"] };

	override evaluate(env: Environment): Environment {
		const subUserInfo = env.getString("userinfo", "sub");
		const subIdToken = env.getString(this.getIdTokenKey(), "claims.sub");

		if (!subUserInfo) {
			throw this.error('"sub" not found in UserInfo response ');
		}

		if (!subIdToken) {
			throw this.error('"sub" not found in ' + this.getIdTokenKey());
		}

		if (subUserInfo !== subIdToken) {
			throw this.error(
				'"sub" in user info response doesn\'t match with "sub" in ' + this.getIdTokenKey(),
				args("sub_user_info", subUserInfo, "sub_id_token", subIdToken),
			);
		}

		this.logSuccess(
			"userinfo response and id_token sub are the same",
			args("sub_user_info", subUserInfo, "sub_id_token", subIdToken),
		);
		return env;
	}

	protected abstract getIdTokenKey(): string;
}
