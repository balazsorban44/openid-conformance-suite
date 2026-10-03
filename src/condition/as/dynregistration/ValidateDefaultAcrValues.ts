import {
	args,
	isJsonArray,
	OIDFJSON,
	UnexpectedJsonTypeException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { AbstractClientValidationCondition, IllegalStateException } from "./AbstractClientValidationCondition.ts";

/**
 * default_acr_values
 *  OPTIONAL. Default requested Authentication Context Class Reference values.
 *  Array of strings that specifies the default acr values that the OP is being
 *  requested to use for processing requests from this Client, with the values
 *  appearing in order of preference. The Authentication Context Class satisfied
 *  by the authentication performed is returned as the acr Claim Value in the
 *  issued ID Token. The acr Claim is requested as a Voluntary Claim by this
 *  parameter. The acr_values_supported discovery element contains a list of the
 *  supported acr values supported by this server. Values specified in the acr_values
 *  request parameter or an individual acr Claim request override these default values.
 *
 */
export class ValidateDefaultAcrValues extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client", "server"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;
		try {
			const defaultAcrValues = this.getDefaultAcrValues();
			if (defaultAcrValues == null) {
				this.logSuccess("default_acr_values is not set");
				return env;
			}
			let acrValuesSupported: Set<string> | null = null;
			const acrValuesSupportedJsonElement = env.getElementFromObject("server", "acr_values_supported");
			if (acrValuesSupportedJsonElement != null && isJsonArray(acrValuesSupportedJsonElement)) {
				acrValuesSupported = new Set<string>();
				for (const acrElement of acrValuesSupportedJsonElement) {
					acrValuesSupported.add(OIDFJSON.getString(acrElement));
				}
			}

			for (const element of defaultAcrValues) {
				try {
					const acrValue = OIDFJSON.getString(element);
					//check if acrValue is one of acr_values_supported if we returned one
					if (acrValuesSupported != null) {
						if (!acrValuesSupported.has(acrValue)) {
							throw this.error(
								"acr value is not one of the supported ones",
								args("acr_values_supported", acrValuesSupportedJsonElement, "offending_value", acrValue),
							);
						}
					}
				} catch (unexpectedTypeEx) {
					if (!(unexpectedTypeEx instanceof UnexpectedJsonTypeException)) {
						throw unexpectedTypeEx;
					}
					throw this.error(
						"default_acr_values contains a value that is not encoded as a string",
						args("element", element),
					);
				}
			}
			this.logSuccess("default_acr_values is valid", args("default_acr_values", defaultAcrValues));
			return env;
		} catch (ex) {
			if (!(ex instanceof IllegalStateException)) {
				throw ex;
			}
			throw this.error(
				"default_acr_values is not encoded as a json array",
				args("default_acr_values", this.client["default_acr_values"]),
			);
		}
	}
}
