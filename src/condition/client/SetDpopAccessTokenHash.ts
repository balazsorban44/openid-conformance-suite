import { createHash } from "node:crypto";
import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetDpopAccessTokenHash extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dpop_proof_claims", "access_token"] };

	override evaluate(env: Environment): Environment {
		const accessToken = env.getString("access_token", "value") as string;

		const claims = env.getObject("dpop_proof_claims") as JsonObject;

		const bytes = Buffer.from(accessToken, "ascii");
		const digest = createHash("sha256").update(bytes).digest();
		const ath = digest.toString("base64url");

		claims["ath"] = ath;

		this.logSuccess("Added ath to DPoP proof claims", args("claims", claims, "access_token", accessToken));

		return env;
	}
}
