import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { JWTUtil } from "../../util/JWTUtil.ts";

export class ExtractClientAssertion extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["client_assertion"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const clientAssertionString = env.getString("token_endpoint_request", "body_form_params.client_assertion");

		if (!clientAssertionString) {
			throw this.error("Could not find client assertion in request parameters");
		}

		let jsonObjectForJwt: JsonObject;
		try {
			// JWTUtil.jwtStringToJsonObjectForEnvironment throws on parse failure (Java: ParseException)
			jsonObjectForJwt = await JWTUtil.jwtStringToJsonObjectForEnvironment(clientAssertionString);
		} catch (e) {
			throw this.error("Couldn't parse client assertion", e, args("client assertion", clientAssertionString));
		}

		env.putObject("client_assertion", jsonObjectForJwt);

		this.logSuccess("Parsed client assertion", args("client_assertion", jsonObjectForJwt));

		return env;
	}
}
