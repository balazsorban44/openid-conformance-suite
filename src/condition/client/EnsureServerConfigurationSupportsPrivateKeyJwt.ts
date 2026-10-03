import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class EnsureServerConfigurationSupportsPrivateKeyJwt extends AbstractCondition {
	static readonly PRIVATEKEY_JWT_AUTH_METHOD = "private_key_jwt";

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const supportedAuthMethods = env.getElementFromObject("server", "token_endpoint_auth_methods_supported");
		if (supportedAuthMethods == null) {
			// Null implies default (only client_secret_basic)
			throw this.error("Only default auth method supported");
		}

		let supportsPrivateKeyJwt = false;
		try {
			// (Java: getAsJsonArray() throws IllegalStateException, which is not caught below)
			if (!isJsonArray(supportedAuthMethods)) {
				throw new Error("Not a JSON Array: " + JSON.stringify(supportedAuthMethods));
			}
			for (const method of supportedAuthMethods) {
				if (EnsureServerConfigurationSupportsPrivateKeyJwt.PRIVATEKEY_JWT_AUTH_METHOD === OIDFJSON.getString(method)) {
					this.logSuccess("Found supported private_key_jwt method", args("method", method));
					supportsPrivateKeyJwt = true;
				}
			}
		} catch (e) {
			// Java: catch (ClassCastException e); OIDFJSON.UnexpectedJsonTypeException is a ClassCastException
			if (e instanceof UnexpectedJsonTypeException) {
				throw this.error(
					"Invalid supported auth methods metadata",
					e,
					args("token_endpoint_auth_methods_supported", supportedAuthMethods),
				);
			}
			throw e;
		}

		if (supportsPrivateKeyJwt) {
			return env;
		} else {
			throw this.error("private_key_jwt is not listed as a supported client authentication method");
		}
	}
}
