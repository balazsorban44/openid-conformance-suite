import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class RejectErrorInUrlQuery extends AbstractCondition {
	override evaluate(env: Environment): Environment {
		if (env.getString("callback_query_params", "error")) {
			throw this.error(
				"'error' is present in URL query returned from authorization endpoint - it should be returned in the URL fragment only",
			);
		}

		this.logSuccess("'error' is not present in URL query returned from authorization endpoint");
		return env;
	}
}
