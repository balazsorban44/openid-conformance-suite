import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CheckMatchingCallbackParameters extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["redirect_uri"], required: ["callback_query_params"] };

	override evaluate(env: Environment): Environment {
		// UriComponentsBuilder.fromUriString(redirect_uri).build().getQueryParams().toSingleValueMap():
		// raw (undecoded) query parameters, first value wins
		const redirectUri = env.getString("redirect_uri") as string;
		const params = new Map<string, string | null>();
		const queryMatch = /^[^?#]*\?([^#]*)/.exec(redirectUri);
		if (queryMatch != null && queryMatch[1] !== "") {
			for (const pair of queryMatch[1].split("&")) {
				if (pair === "") {
					continue;
				}
				const eq = pair.indexOf("=");
				const name = eq === -1 ? pair : pair.substring(0, eq);
				const value = eq === -1 ? null : pair.substring(eq + 1);
				if (!params.has(name)) {
					params.set(name, value);
				}
			}
		}

		const o: JsonObject = {}; // For the log

		for (const [key, expected] of params) {
			const actual = env.getString("callback_query_params", key);

			// UPSTREAM: Java's expected.equals(actual) throws a NullPointerException for a parameter without a value
			if (expected !== actual) {
				throw this.error(
					"The client should have been registered with a redirect uri that contains ?dummy1=lorem&dummy2=ipsum (as per instructions), and this url was passed as the redirect uri to the authorization endpoint. These parameters must be present in the redirect back, but they are not.",
					args("parameter", key, "expected", expected, "actual", actual),
				);
			}

			o[key] = expected;
		}

		this.logSuccess("Callback parameters successfully verified", o);

		return env;
	}
}
