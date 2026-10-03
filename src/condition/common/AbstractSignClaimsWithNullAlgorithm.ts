import { AbstractCondition, args, type Environment, type JsonObject } from "../../framework/index.ts";
import { JWTUtil, ParseException } from "../../util/JWTUtil.ts";

export abstract class AbstractSignClaimsWithNullAlgorithm extends AbstractCondition {
	protected abstract getClaimsNotFoundErrorMsg(): string;
	protected abstract getSuccessMsg(): string;

	protected signWithNullAlgorithm(env: Environment, claimsSourceKey: string, jwtTargetKey: string): Environment {
		const objectClaims = env.getObject(claimsSourceKey);

		if (objectClaims == null) {
			throw this.error(this.getClaimsNotFoundErrorMsg());
		}

		try {
			// JWTClaimsSet.parse(objectClaims.toString()) followed by claimSet.toJSONObject()
			const claimSet: JsonObject = JWTUtil.jwtClaimsSetAsJsonObject({
				type: "plain",
				serialized: "",
				parts: [],
				header: {},
				payload: JSON.stringify(objectClaims),
				signature: null,
			});
			// toJSONObject() (as opposed to toJSONObject(true)) omits claims with null values
			for (const name of Object.keys(claimSet)) {
				if (claimSet[name] === null) {
					delete claimSet[name];
				}
			}

			// new PlainHeader()
			const header: JsonObject = { alg: "none" };

			// new PlainJWT(header, claimSet).serialize(): the unsecured JWT has an empty third part
			const serialized =
				Buffer.from(JSON.stringify(header)).toString("base64url") +
				"." +
				Buffer.from(JSON.stringify(claimSet)).toString("base64url") +
				".";

			env.putString(jwtTargetKey, serialized);

			this.logSuccess(
				this.getSuccessMsg(),
				args("header", header, "claims", claimSet, jwtTargetKey + "_serialized", serialized),
			);

			return env;
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error(e);
			}
			throw e;
		}
	}
}
