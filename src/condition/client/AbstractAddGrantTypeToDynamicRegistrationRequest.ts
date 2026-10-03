import { AbstractCondition, args, type Environment, type JsonArray, type JsonObject } from "../../framework/index.ts";

export abstract class AbstractAddGrantTypeToDynamicRegistrationRequest extends AbstractCondition {
	protected addGrantType(env: Environment, toAdd: string): void {
		const dynamicRegistrationRequest = env.getObject("dynamic_registration_request") as JsonObject;
		let grantTypes: JsonArray = [];
		const grant_types = "grant_types";
		if (grant_types in dynamicRegistrationRequest) {
			grantTypes = dynamicRegistrationRequest[grant_types] as JsonArray;
		}
		grantTypes.push(toAdd);
		dynamicRegistrationRequest[grant_types] = grantTypes;
		env.putObject("dynamic_registration_request", dynamicRegistrationRequest);

		this.log("Added '" + toAdd + "' to '" + grant_types + "'", args(grant_types, grantTypes));
	}
}
