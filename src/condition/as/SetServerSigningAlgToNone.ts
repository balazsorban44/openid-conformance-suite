import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class SetServerSigningAlgToNone extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["signing_algorithm"] };

	override evaluate(env: Environment): Environment {
		env.putString("signing_algorithm", "none");

		this.log("Successfully set signing algorithm to none", args("signing_algorithm", "none"));

		return env;
	}
}
