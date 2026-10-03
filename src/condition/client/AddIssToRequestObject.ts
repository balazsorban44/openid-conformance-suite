import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddIssToRequestObject extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["request_object_claims"] };

	override evaluate(env: Environment): Environment {
		const requestObjectClaims = env.getObject("request_object_claims") as JsonObject;

		const clientId = env.getString("client", "client_id");

		if (clientId != null) {
			requestObjectClaims["iss"] = clientId;

			env.putObject("request_object_claims", requestObjectClaims);

			this.logSuccess("Added iss to request object claims", args("iss", clientId));
		} else {
			// Only a "should" requirement
			this.log("Request object contains no issuer and client ID not found");
		}

		return env;
	}
}
