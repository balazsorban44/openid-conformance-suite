import { AbstractCondition, args, type Environment } from "../../framework/index.ts";

export abstract class AbstractCheckErrorFromResponseError extends AbstractCondition {
	protected abstract getResponseKey(): string;

	protected abstract getExpectedError(): string[];

	override evaluate(env: Environment): Environment {
		if (!env.containsObject(this.getResponseKey())) {
			throw this.error("Couldn't find " + this.getResponseKey());
		}

		const error = this.getError(env);
		if (!error) {
			throw this.error("Couldn't find error field");
		}

		const expected = this.getExpectedError();
		if (!expected.includes(error)) {
			throw this.error("'error' field has unexpected value", args("expected", expected, "actual", error));
		}

		this.logSuccess(
			this.getResponseKey() + " error returned expected 'error' of '" + error + "'",
			args("expected", expected),
		);
		return env;
	}

	protected getError(env: Environment): string | null {
		return env.getString(this.getResponseKey(), "error");
	}
}
