import {
	AbstractCondition,
	has,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class FilterUserInfoForScopes extends AbstractCondition {
	private static scopesToClaims: Map<string, Set<string>> = new Map();

	static {
		const put = (scope: string, claim: string): void => {
			let claims = FilterUserInfoForScopes.scopesToClaims.get(scope);
			if (claims === undefined) {
				claims = new Set();
				FilterUserInfoForScopes.scopesToClaims.set(scope, claims);
			}
			claims.add(claim);
		};

		put("openid", "sub");

		put("profile", "name");
		put("profile", "preferred_username");
		put("profile", "given_name");
		put("profile", "family_name");
		put("profile", "middle_name");
		put("profile", "nickname");
		put("profile", "profile");
		put("profile", "picture");
		put("profile", "website");
		put("profile", "gender");
		put("profile", "zoneinfo");
		put("profile", "locale");
		put("profile", "updated_at");
		put("profile", "birthdate");

		put("email", "email");
		put("email", "email_verified");

		put("phone", "phone_number");
		put("phone", "phone_number_verified");

		put("address", "address");
	}

	static override pre: EnvironmentRequirements = { strings: ["scope"], required: ["user_info"] };
	static override post: EnvironmentRequirements = { required: ["user_info_endpoint_response"] };

	override evaluate(env: Environment): Environment {
		const scope = env.getString("scope") as string;
		const userInfo = env.getObject("user_info") as JsonObject;

		const scopes = scope.split(" ");

		const out: JsonObject = {};

		// look through all the scopes that we have approved
		for (const s of scopes) {
			const claims = FilterUserInfoForScopes.scopesToClaims.get(s);
			if (claims !== undefined) {
				for (const claim of claims) {
					if (has(userInfo, claim)) {
						// if we have a claim that fits that scope, copy it over
						out[claim] = userInfo[claim];
					}
				}
			}
		}

		env.putObject("user_info_endpoint_response", out);

		this.logSuccess("User info endpoint output", out);

		return env;
	}
}
