import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { RFC6749AppendixASyntaxUtils } from "../../util/RFC6749AppendixASyntaxUtils.ts";

export class OIDCCRegisterClient extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["dynamic_registration_request"] };
	static override post: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("dynamic_registration_request") as JsonObject;
		const randomStr = RFC6749AppendixASyntaxUtils.generateVSChar(15, 5, 5);
		client["client_id"] = "client_" + randomStr;
		env.putObject("client", client);
		this.logSuccess("Registered client", args("client", client));
		return env;
	}
}
