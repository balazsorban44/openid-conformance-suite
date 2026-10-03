import {
	AbstractCondition,
	args,
	isJsonObject,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
	type JsonValue,
} from "../../framework/index.ts";

/** Port of JsonElement.getAsJsonObject(), which throws IllegalStateException if the element is not an object */
function getAsJsonObject(element: JsonValue | undefined): JsonObject {
	if (!isJsonObject(element)) {
		throw new Error("Not a JSON Object: " + JSON.stringify(element));
	}
	return element;
}

export class EnsureMemberValuesInClaimNameReferenceToMemberNamesInClaimSources extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["userinfo"] };

	override evaluate(env: Environment): Environment {
		const claimNames = env.getElementFromObject("userinfo", "_claim_names");
		const claimSources = env.getElementFromObject("userinfo", "_claim_sources");

		if (claimNames == null && claimSources == null) {
			this.log("userinfo response does not contain '_claim_names' nor _claim_sources'");
		} else if (claimNames == null) {
			throw this.error("userinfo response contains '_claim_sources' but not _claim_names'");
		} else if (claimSources == null) {
			throw this.error("userinfo response contains '_claim_names' but not _claim_sources'");
		} else {
			const memberValuesInClaimNames = new Set<string>();
			for (const keyClaimName of Object.keys(getAsJsonObject(claimNames))) {
				memberValuesInClaimNames.add(OIDFJSON.getString(getAsJsonObject(claimNames)[keyClaimName]));
			}

			for (const keyClaimSource of Object.keys(getAsJsonObject(claimSources))) {
				if (!memberValuesInClaimNames.has(keyClaimSource)) {
					throw this.error(
						"Member name '" +
							keyClaimSource +
							"' in userinfo response '_claim_sources' is not referenced by member values in '_claim_names'",
						args("_claim_names", claimNames, "_claim_sources", claimSources),
					);
				}
			}

			this.logSuccess(
				"userinfo response member names in '_claim_sources' are all referenced by member values in '_claim_names'",
				args("_claim_names", claimNames, "_claim_sources", claimSources),
			);
		}

		return env;
	}
}
