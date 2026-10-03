import { args, type Environment, type EnvironmentRequirements, type JsonObject } from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 * subject_type
 * OPTIONAL. subject_type requested for responses to this Client. The subject_types_supported
 * Discovery parameter contains a list of the supported subject_type values for this server.
 * Valid types include pairwise and public.
 */
export class ValidateClientSubjectType extends AbstractClientValidationCondition {
	static readonly ALLOWED_SUBJECT_TYPES: ReadonlySet<string> = new Set(["public", "pairwise"]);

	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const subjectType = this.getSubjectType();
		if (subjectType == null) {
			this.logSuccess("A subject_type was not provided");
			return env;
		}

		if (ValidateClientSubjectType.ALLOWED_SUBJECT_TYPES.has(subjectType)) {
			this.logSuccess("subject_type is valid", args("subject_type", subjectType));
			return env;
		}
		throw this.error("Unexpected subject_type", args("subject_type", subjectType));
	}
}
