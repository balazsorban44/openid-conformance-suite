import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class SetClientIdTokenSignedResponseAlgToServerSigningAlg extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"], strings: ["signing_algorithm"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;
		const signingAlg = env.getString("signing_algorithm");
		client["id_token_signed_response_alg"] = signingAlg;
		env.putObject("client", client);
		this.log(
			"Set id_token_signed_response_alg for the registered client",
			args("id_token_signed_response_alg", signingAlg),
		);
		return env;
	}
}
