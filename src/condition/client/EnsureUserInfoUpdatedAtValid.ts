import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractUpdatedAtValid } from "./AbstractUpdatedAtValid.ts";

export class EnsureUserInfoUpdatedAtValid extends AbstractUpdatedAtValid {
	static readonly location = "userinfo";

	static override pre: EnvironmentRequirements = { required: [EnsureUserInfoUpdatedAtValid.location] };

	override evaluate(env: Environment): Environment {
		return this.validateUpdatedAt(env, EnsureUserInfoUpdatedAtValid.location);
	}
}
