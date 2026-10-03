import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class OIDCCCheckIdTokenSigningAlgValuesSupportedAlgNone extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };

	override evaluate(env: Environment): Environment {
		const idTokenSigningAlgSupported = env.getElementFromObject("server", "id_token_signing_alg_values_supported");

		let errorMessage: string | null = null;

		if (idTokenSigningAlgSupported == null) {
			errorMessage = "'id_token_signing_alg_values_supported' is null";
		} else if (!isJsonArray(idTokenSigningAlgSupported)) {
			errorMessage = "'id_token_signing_alg_values_supported' is not a json array";
		} else {
			// convert JsonArray idTokenSigningAlgSupported to list string
			const idTokenSigningAlgSupportedList: string[] = [];
			for (const alg of idTokenSigningAlgSupported) {
				idTokenSigningAlgSupportedList.push(OIDFJSON.getString(alg));
			}

			if (!idTokenSigningAlgSupportedList.includes("none")) {
				errorMessage = "'id_token_signing_alg_values_supported' doesn't contain 'none' algorithm'";
			}
		}

		if (errorMessage != null) {
			// skip test when id_token_signing_alg_values_supported is not supported 'none' algorithm
			env.putBoolean("id_token_signing_alg_not_supported_flag", true);
			throw this.error(errorMessage, args("id_token_signing_alg_values_supported", idTokenSigningAlgSupported));
		}

		this.logSuccess(
			"'id_token_signing_alg_values_supported' contain 'none' algorithm",
			args("id_token_signing_alg_values_supported", idTokenSigningAlgSupported),
		);

		return env;
	}
}
