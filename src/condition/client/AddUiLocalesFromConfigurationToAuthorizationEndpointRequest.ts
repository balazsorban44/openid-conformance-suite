import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddUiLocalesFromConfigurationToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request", "config"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		let uiLocales = env.getString("config", "server.ui_locales");
		let msg: string;
		if (!uiLocales) {
			uiLocales = "se";

			msg = "No ui_locales in test configuration, added ui_locales=se to authorization endpoint request";
		} else {
			msg = "Added ui_locales from test configuration to authorization endpoint request";
		}

		authorizationEndpointRequest["ui_locales"] = uiLocales;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess(msg, authorizationEndpointRequest);

		return env;
	}
}
