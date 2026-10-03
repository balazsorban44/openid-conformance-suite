import {
	AbstractCondition,
	RandomStringUtils,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CreateDpopClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	static override post: EnvironmentRequirements = { required: ["dpop_proof_claims"] };

	override evaluate(env: Environment): Environment {
		const claims: JsonObject = {};
		claims["jti"] = RandomStringUtils.nextAlphanumeric(20);

		const iat = Math.floor(Date.now() / 1000);
		claims["iat"] = iat;

		this.logSuccess("Created DPoP proof claims", claims);

		env.putObject("dpop_proof_claims", claims);

		return env;
	}
}
