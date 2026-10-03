import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class EnsureServerConfigurationSupportsMTLS extends AbstractCondition {
	static readonly MTLS_AUTH_METHODS: string[] = ["tls_client_auth", "self_signed_tls_client_auth"];

	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const supportedAuthMethods = env.getElementFromObject("server", "token_endpoint_auth_methods_supported");
		if (supportedAuthMethods == null) {
			// Null implies default (only client_secret_basic)
			throw this.error("Only default auth method supported");
		}

		let supportsMtls = false;
		try {
			// (Java: getAsJsonArray() throws IllegalStateException, which is not caught below)
			if (!isJsonArray(supportedAuthMethods)) {
				throw new Error("Not a JSON Array: " + JSON.stringify(supportedAuthMethods));
			}
			for (const method of supportedAuthMethods) {
				if (EnsureServerConfigurationSupportsMTLS.MTLS_AUTH_METHODS.includes(OIDFJSON.getString(method))) {
					this.logSuccess("Found supported MTLS method", args("method", method));
					supportsMtls = true;
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

		if (supportsMtls) {
			return env;
		} else {
			throw this.error(
				"No MTLS auth methods supported",
				args("token_endpoint_auth_methods_supported", supportedAuthMethods),
			);
		}
	}
}
