import {
	AbstractCondition,
	args,
	has,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * This copies any server endpoints into the root of the environment, overriding it with any entry found in
 * mtls_endpoint_aliases.
 *
 * It is assumed that, when a test needs to use mtls, it will use the value in the root of the
 * environment.
 */
export class AddMTLSEndpointAliasesToEnvironment extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const server = env.getObject("server") as JsonObject;

		const mtlsEndpointAliasesEl = env.getElementFromObject("server", "mtls_endpoint_aliases");
		let mtlsEndpointAliases: JsonObject | null = null;

		const allKeys = new Set<string>();
		for (const k of Object.keys(server)) {
			allKeys.add(k);
		}
		if (mtlsEndpointAliasesEl !== undefined) {
			if (!isJsonObject(mtlsEndpointAliasesEl)) {
				throw this.error(
					"mtls_endpoint_aliases in the server configuration is not a JSON object",
					args("server", server),
				);
			}

			mtlsEndpointAliases = mtlsEndpointAliasesEl;
			for (const k of Object.keys(mtlsEndpointAliases)) {
				allKeys.add(k);
			}
		}

		for (const k of allKeys) {
			if (k.endsWith("_endpoint")) {
				let jsonElement = undefined;

				if (mtlsEndpointAliases != null) {
					jsonElement = mtlsEndpointAliases[k];
				}

				if (jsonElement !== undefined) {
					env.putString(k, OIDFJSON.getString(jsonElement));
				} else {
					env.putString(k, OIDFJSON.getString(server[k]));
				}
			}
		}

		this.logSuccess("Added mtls_endpoint_aliases to environment");

		if (mtlsEndpointAliases != null) {
			if (has(mtlsEndpointAliases, "authorization_endpoint")) {
				throw this.error(
					"authorization_endpoint is incorrectly listed in mtls_endpoint_aliases - as per RFC8705 section 5 only endpoints the client makes a direct call are listed here.",
					mtlsEndpointAliases,
				);
			}

			for (const k of Object.keys(mtlsEndpointAliases)) {
				if (!k.endsWith("_endpoint")) {
					throw this.error(
						"unexpected value '" +
							k +
							"' found in mtls_endpoint_aliases. Only endpoints the client makes a direct call are listed here",
						mtlsEndpointAliases,
					);
				}
			}
			const keysOnlyInMtlsEndpointAliases = new Set<string>();
			for (const k of Object.keys(mtlsEndpointAliases)) {
				keysOnlyInMtlsEndpointAliases.add(k);
			}
			for (const k of Object.keys(server)) {
				keysOnlyInMtlsEndpointAliases.delete(k);
			}
			if (keysOnlyInMtlsEndpointAliases.size > 0) {
				throw this.error(
					"Some endpoints are found only in mtls_endpoint_aliases. Endpoints should only be present in mtls_endpoint_aliases if an endpoint has versions that both do and do not require mtls.",
					args("mtls_endpoint_aliases", mtlsEndpointAliases, "only_in_mtls", [...keysOnlyInMtlsEndpointAliases]),
				);
			}
		}

		return env;
	}
}
