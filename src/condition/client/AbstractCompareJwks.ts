import {
	AbstractCondition,
	jsonEquals,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonArray,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Java `Set<JsonObject>` (a HashSet using Gson's structural equality) is represented as an array without
 * structurally equal duplicates.
 */
export abstract class AbstractCompareJwks extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["original_jwks", "new_jwks"] };

	/** Adds `o` to the set `set` unless a structurally equal object is already present (Java `Set.add`). */
	protected static addToSet(set: JsonObject[], o: JsonObject): void {
		if (!set.some((x) => jsonEquals(x, o))) {
			set.push(o);
		}
	}

	/** Java `Set.contains` with Gson equality */
	protected static setContains(set: JsonObject[], o: JsonObject): boolean {
		return set.some((x) => jsonEquals(x, o));
	}

	filterJsonArrayToSetContainingSigningKeys(keys: JsonArray): JsonObject[] {
		const filtered: JsonObject[] = [];

		keys.forEach((keyJsonElement) => {
			const keyObject = keyJsonElement as JsonObject;

			const use = keyObject["use"];

			if (use == null || OIDFJSON.getString(use) === "sig") {
				// 'use' attribute is completely optional, so we include use: sig or no use claim
				AbstractCompareJwks.addToSet(filtered, keyObject);
			}
		});
		return filtered;
	}

	override evaluate(env: Environment): Environment {
		// This condition would be a lot easier to write/more robust if we knew which key the OP was & now is using
		// to sign id_tokens - but the python version of this test doesn't do an authentication
		const originalKeys = (env.getObject("original_jwks") as JsonObject)["keys"] as JsonArray;
		const newKeys = (env.getObject("new_jwks") as JsonObject)["keys"] as JsonArray;

		const originalSigningKeys = this.filterJsonArrayToSetContainingSigningKeys(originalKeys);
		const latestSigningKeys = this.filterJsonArrayToSetContainingSigningKeys(newKeys);

		this.compareJwks(originalSigningKeys, latestSigningKeys);

		return env;
	}

	protected abstract compareJwks(originalSigningKeys: JsonObject[], latestSigningKeys: JsonObject[]): void;
}
