import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class AddLoginHintFromConfigurationToAuthorizationEndpointRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["authorization_endpoint_request", "config"] };
	static override post: EnvironmentRequirements = { required: ["authorization_endpoint_request"] };

	override evaluate(env: Environment): Environment {
		const authorizationEndpointRequest = env.getObject("authorization_endpoint_request") as JsonObject;

		let loginHint = env.getString("config", "server.login_hint");
		let msg: string;
		if (!loginHint) {
			const issuer = env.getString("server", "issuer");
			try {
				const issuerUri = new URL(issuer as string);

				loginHint = "buffy@" + issuerUri.hostname;
			} catch (e) {
				throw this.error("Couldn't parse issuer as URL", e, args("issuer", issuer));
			}

			msg =
				"No login_hint in test configuration, created one based on issuer and added login_hint to authorization endpoint request";
		} else {
			msg = "Added login_hint from test configuration to authorization endpoint request";
		}

		authorizationEndpointRequest["login_hint"] = loginHint;

		env.putObject("authorization_endpoint_request", authorizationEndpointRequest);

		this.logSuccess(msg, authorizationEndpointRequest);

		return env;
	}
}
