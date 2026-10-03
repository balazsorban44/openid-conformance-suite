import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureUserInfoDoesNotContainNonce extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["userinfo"] };

	override evaluate(env: Environment): Environment {
		const nonce = env.getString("userinfo", "nonce");

		if (nonce != null) {
			throw this.error(
				"The signed userinfo response contains 'nonce'. Nonce is not listed in section 5.1 of the OpenID Connect Core specification, and hence should not be returned in the userinfo response. A signed userinfo response that contains nonce is potentially a security issue, as it may be mistaken for an id_token - particularly if it also contains the 'iat' and 'exp' claims.",
			);
		}

		this.logSuccess(
			"userinfo response does not contain 'nonce' and hence cannot be confused with an id_token.",
			args("nonce", nonce),
		);

		return env;
	}
}
