import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class SetClientIdTokenSignedResponseAlgToNone extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;
		client["id_token_signed_response_alg"] = "none";
		env.putObject("client", client);
		this.log("Set id_token_signed_response_alg to none for the registered client", args("client", client));
		return env;
	}
}
