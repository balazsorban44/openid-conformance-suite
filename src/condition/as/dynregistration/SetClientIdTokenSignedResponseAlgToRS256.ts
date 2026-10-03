import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class SetClientIdTokenSignedResponseAlgToRS256 extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;
		client["id_token_signed_response_alg"] = "RS256";
		env.putObject("client", client);
		this.log("Set id_token_signed_response_alg to RS256 for the registered client", args("client", client));
		return env;
	}
}
