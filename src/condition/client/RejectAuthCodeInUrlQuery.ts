import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class RejectAuthCodeInUrlQuery extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["callback_query_params"] };

	override evaluate(env: Environment): Environment {
		if (env.getString("callback_query_params", "code")) {
			throw this.error(
				"Authorization code is present in URL query returned from authorization endpoint - hybrid/implicit flow require it to be returned in the URL fragment/hash only",
			);
		}

		this.logSuccess("Authorization code is not present in URL query returned from authorization endpoint");
		return env;
	}
}
