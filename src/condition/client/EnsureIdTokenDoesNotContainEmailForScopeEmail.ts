import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class EnsureIdTokenDoesNotContainEmailForScopeEmail extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["id_token"] };

	override evaluate(env: Environment): Environment {
		const email = env.getString("id_token", "claims.email");

		if (email != null) {
			// see discussion on certification email list, 10th March 2020
			throw this.error(
				"Unexpectedly found email in id_token. The conformance suite did not request the 'email' claim is returned in the id_token and hence did not expect the server to include it; as per the spec link for this response_type scope=email is a short hand for 'please give me access to the user's email address in the userinfo response'. Technically returning unrequested claims does not violate the specifications but it could be a bug in the server and may result in user data being exposed in unintended ways if the relying party did not expect the email to be in the id_token, and then uses the id_token to provide proof of the authentication event to other parties.",
				args("email", email),
			);
		}

		this.logSuccess(
			"email claim not found in id_token, which is expected as it was not requested to be returned there",
		);

		return env;
	}
}
