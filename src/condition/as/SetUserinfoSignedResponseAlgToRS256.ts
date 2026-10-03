import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class SetUserinfoSignedResponseAlgToRS256 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;

		client["userinfo_signed_response_alg"] = "RS256";

		this.log("Set userinfo_signed_response_alg to RS256");

		env.putObject("client", client);

		return env;
	}
}
