import { AbstractCondition, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class SetServerSigningAlgToRS256 extends AbstractCondition {
	static override post: EnvironmentRequirements = { strings: ["signing_algorithm"] };

	override evaluate(env: Environment): Environment {
		env.putString("signing_algorithm", "RS256");

		this.log("Successfully set signing algorithm to RS256");

		return env;
	}
}
