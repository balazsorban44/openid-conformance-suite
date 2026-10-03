import { AbstractCondition, args, type Environment } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export abstract class AbstractEnsureResponseType extends AbstractCondition {
	protected ensureResponseTypeMatches(env: Environment, ...types: string[]): Environment {
		const responseTypeString = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.RESPONSE_TYPE,
		);
		if (!responseTypeString) {
			throw this.error("Could not find response type in request");
		}

		const expectedString = types.join(" ");

		// UPSTREAM: Java's Set.of() throws IllegalArgumentException on duplicate elements (e.g. "code code"); a JS Set silently dedupes
		const responseType = new Set(responseTypeString.split(" "));
		const expected = new Set(types);

		if (responseType.size !== expected.size || ![...responseType].every((t) => expected.has(t))) {
			throw this.error(
				"Response type is not expected value",
				args("expected", expectedString, "actual", responseTypeString),
			);
		} else {
			this.logSuccess("Response type is expected value", args("expected", expectedString));
			return env;
		}
	}
}
