import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractUpdatedAtValid } from "./AbstractUpdatedAtValid.ts";

export class EnsureIdTokenUpdatedAtValid extends AbstractUpdatedAtValid {
	static readonly location = "id_token";

	static override pre: EnvironmentRequirements = { required: [EnsureIdTokenUpdatedAtValid.location] };

	override evaluate(env: Environment): Environment {
		return this.validateUpdatedAt(env, EnsureIdTokenUpdatedAtValid.location);
	}
}
