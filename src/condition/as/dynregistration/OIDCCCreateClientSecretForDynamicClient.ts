import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { RFC6749AppendixASyntaxUtils } from "../../util/RFC6749AppendixASyntaxUtils.ts";

export class OIDCCCreateClientSecretForDynamicClient extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;
		//HS256 requires at least 64 characters
		const randomStr = RFC6749AppendixASyntaxUtils.generateVSChar(50, 10, 5);
		const secret = "secret_" + randomStr;
		client["client_secret"] = secret;
		client["client_secret_expires_at"] = 0;
		env.putObject("client", client);
		this.log("Set the secret for registered client", args("client_secret", secret));
		return env;
	}
}
