import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/**
 * Must be called after a FilterUserInfoForScopes call
 * Use to add userinfo claims filtered by scopes to id_token
 */
export class AddUserinfoClaimsToIdTokenClaims extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token_claims", "user_info_endpoint_response"] };
	static override post: EnvironmentRequirements = { required: ["id_token_claims"] };

	override evaluate(env: Environment): Environment {
		const userInfoEndpointResponse = env.getObject("user_info_endpoint_response") as JsonObject;
		const idTokenClaims = env.getObject("id_token_claims") as JsonObject;
		for (const claimName of Object.keys(userInfoEndpointResponse)) {
			idTokenClaims[claimName] = userInfoEndpointResponse[claimName];
		}

		env.putObject("id_token_claims", idTokenClaims);

		this.log("Added userinfo claims to ID Token Claims", idTokenClaims);

		return env;
	}
}
