import { AbstractCondition, args, OIDFJSON, type Environment, type JsonValue } from "../../framework/index.ts";

export abstract class AbstractJsonUriIsValidAndHttps extends AbstractCondition {
	protected static readonly requiredProtocol = "https";
	protected static readonly errorMessageInvalidURL = "Invalid URL. Unable to parse.";

	/***
	 * Get the named URL value from the "server" environment object. Must not memoize across calls:
	 * callers such as CheckDiscEndpointAllEndpointsAreHttps invoke validate() once per endpoint on
	 * the same instance, so a cached value would make every endpoint validate the first one's URL.
	 */
	protected getServerValueOrDie(env: Environment, environmentVariable: string): JsonValue {
		const serverValue = env.getElementFromObject("server", environmentVariable);
		if (serverValue == null) {
			throw this.error(environmentVariable + ": URL not found");
		}
		return serverValue;
	}

	/***
	 * Parse a URL from {@code serverValue}, which must be a JSON string. {@code fieldName} identifies
	 * the field in the failure messages so they say what was wrong with which value.
	 */
	protected extractURLOrDie(serverValue: JsonValue, fieldName: string): URL {
		if (!OIDFJSON.isString(serverValue)) {
			throw this.error(fieldName + " is expected to be a string containing a URL", args("actual", serverValue));
		}
		const url = OIDFJSON.getString(serverValue);
		try {
			return new URL(url);
		} catch (invalidURL) {
			throw this.error(
				fieldName + " is not a valid URL",
				args("actual", url, "parse_error", (invalidURL as Error).message),
			);
		}
	}

	/***
	 * Validates a specific environment variable URL's protocol
	 */
	validate(env: Environment, environmentVariable: string): Environment {
		const server = this.getServerValueOrDie(env, environmentVariable);
		const theURL = this.extractURLOrDie(server, environmentVariable);

		// Java's URL.getProtocol() has no trailing colon
		const protocol = theURL.protocol.replace(/:$/, "");
		if (protocol !== AbstractJsonUriIsValidAndHttps.requiredProtocol) {
			throw this.error(
				environmentVariable + " must use the " + AbstractJsonUriIsValidAndHttps.requiredProtocol + " scheme",
				args("required", AbstractJsonUriIsValidAndHttps.requiredProtocol, "actual_scheme", protocol, "actual", server),
			);
		}

		this.logSuccess(environmentVariable, args("actual", server));

		return env;
	}
}
