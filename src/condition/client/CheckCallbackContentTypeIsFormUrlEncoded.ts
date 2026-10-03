import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CheckCallbackContentTypeIsFormUrlEncoded extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["callback_headers"] };

	override evaluate(env: Environment): Environment {
		const contentType = env.getString("callback_headers", "content-type");
		const expected = "application/x-www-form-urlencoded";

		if (contentType == null) {
			throw this.error("content-type header to redirect_uri is missing", args("expected", expected));
		}

		if (contentType !== expected) {
			throw this.error(
				"content-type header to redirect_uri does not have the expected value",
				args("content_type", contentType, "expected", expected),
			);
		}

		this.logSuccess(
			"content-type header to redirect_uri has the expected value",
			args("content_type", contentType, "expected", expected),
		);
		return env;
	}
}
