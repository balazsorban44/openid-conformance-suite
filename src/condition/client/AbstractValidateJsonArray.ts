import {
	AbstractCondition,
	args,
	isJsonArray,
	OIDFJSON,
	type Environment,
	type JsonArray,
} from "../../framework/index.ts";

export abstract class AbstractValidateJsonArray extends AbstractCondition {
	countMatchingElements(searchValues: string[], searchSpace: JsonArray): number {
		let foundCount = 0;

		for (const searchValue of searchValues) {
			for (const json of searchSpace) {
				if (this.elementsEqual(searchValue, OIDFJSON.getString(json))) {
					foundCount++;
					break;
				}
			}
		}
		return foundCount;
	}

	protected elementsEqual(e1: string, e2: string): boolean {
		return e1 === e2;
	}

	validate(
		env: Environment,
		environmentVariable: string,
		setValues: string[],
		minimumMatchesRequired: number,
		errorMessageNotEnough: string | null,
	): Environment {
		const serverValues = env.getElementFromObject("server", environmentVariable);
		let errorMessage: string | null = null;

		if (serverValues === undefined) {
			errorMessage = environmentVariable + ": not found";
		} else {
			if (!isJsonArray(serverValues)) {
				errorMessage = "'" + environmentVariable + "' should be an array";
			} else {
				if (this.countMatchingElements(setValues, serverValues) < minimumMatchesRequired) {
					errorMessage = errorMessageNotEnough;
				}
			}
		}

		if (errorMessage != null) {
			if (minimumMatchesRequired === 1) {
				throw this.error(
					errorMessage,
					args(
						"discovery_metadata_key",
						environmentVariable,
						"expected_at_least_one_of",
						setValues,
						"actual",
						serverValues ?? null,
					),
				);
			}
			throw this.error(
				errorMessage,
				args("discovery_metadata_key", environmentVariable, "expected", setValues, "actual", serverValues ?? null),
			);
		}

		this.logSuccess(
			"Contents of '" + environmentVariable + "' in discovery document matches expectations.",
			args("actual", serverValues ?? null, "expected", setValues, "minimum_matches_required", minimumMatchesRequired),
		);

		return env;
	}
}
