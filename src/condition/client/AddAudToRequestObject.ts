import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddAudToRequestObject extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["request_object_claims"] };

	override evaluate(env: Environment): Environment {
		const requestObjectClaims = env.getObject("request_object_claims") as JsonObject;

		const serverIssuerUrl = env.getString("server", "issuer");

		if (serverIssuerUrl != null) {
			requestObjectClaims["aud"] = serverIssuerUrl;

			env.putObject("request_object_claims", requestObjectClaims);

			this.logSuccess("Added aud to request object claims", args("aud", serverIssuerUrl));
		} else {
			// Only a "should" requirement
			this.log("Request object contains no audience and server issuer URL not found");
		}

		return env;
	}
}
