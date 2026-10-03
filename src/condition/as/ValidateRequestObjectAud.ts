import {
	AbstractCondition,
	args,
	isJsonArray,
	jsonArrayContains,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class ValidateRequestObjectAud extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_request_object", "client"] };

	override evaluate(env: Environment): Environment {
		const issuer = env.getString("server", "issuer") as string; // to validate the audience

		const aud = env.getElementFromObject("authorization_request_object", "claims.aud");
		if (aud === undefined) {
			throw this.error("Missing audience, request object does not contain an 'aud' claim");
		}

		if (isJsonArray(aud)) {
			if (!jsonArrayContains(aud, issuer)) {
				throw this.error(
					"aud claim values does not include the suite's issuer identifier",
					args("expected", issuer, "actual", aud),
				);
			}
		} else {
			if (issuer !== OIDFJSON.getString(aud)) {
				throw this.error(
					"aud claim value does not match the suite's issuer identifier",
					args("expected", issuer, "actual", aud),
				);
			}
		}

		this.logSuccess("aud claim matches the suite's issuer identifier", args("aud", aud));

		return env;
	}
}
