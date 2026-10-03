import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JWKUtil, ParseException, type JWK } from "../../util/JWKUtil.ts";

export class CreateDpopHeader extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };
	static override post: EnvironmentRequirements = { required: ["dpop_proof_header"] };

	private getPublicJwk(jwk: JsonObject): JsonObject {
		let parsedJwk: JWK | null = null;
		try {
			parsedJwk = JWKUtil.parseJWK(JSON.stringify(jwk));
		} catch (e) {
			if (e instanceof ParseException) {
				throw this.error("Invalid DPoP JWK", e, args("jwk", jwk));
			}
			throw e;
		}
		// UPSTREAM: Java throws a NullPointerException for a symmetric key (toPublicJWK() returns null)
		const pubObj = JWKUtil.toPublicJWK(parsedJwk) as JsonObject;

		return pubObj;
	}

	override evaluate(env: Environment): Environment {
		const jwk = env.getElementFromObject("client", "dpop_private_jwk") as JsonObject;

		const pubObj = this.getPublicJwk(jwk);

		const header: JsonObject = {};

		header["alg"] = OIDFJSON.getString(jwk["alg"]); // use alg in jwk
		header["typ"] = "dpop+jwt";
		header["jwk"] = pubObj;

		env.putObject("dpop_proof_header", header);

		this.logSuccess("Created DPoP proof header", header);

		return env;
	}
}
