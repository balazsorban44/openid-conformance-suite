import {
	AbstractCondition,
	args,
	ConditionError,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";
import { TLSTestValueExtractor } from "../util/TLSTestValueExtractor.ts";

export class ExtractTLSTestValuesFromServerConfiguration extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server"] };
	// always required, others are added as found: authorization_endpoint_tls, userinfo_endpoint_tls, registration_endpoint_tls
	static override post: EnvironmentRequirements = { required: ["token_endpoint_tls"] };

	override evaluate(env: Environment): Environment {
		try {
			const authorizationEndpoint =
				env.getString("authorization_endpoint") != null
					? env.getString("authorization_endpoint")
					: env.getString("server", "authorization_endpoint");

			let authorizationEndpointTls: JsonObject | null = null;
			if (authorizationEndpoint) {
				authorizationEndpointTls = TLSTestValueExtractor.extractTlsFromUrl(authorizationEndpoint);
				env.putObject("authorization_endpoint_tls", authorizationEndpointTls);
			}

			const tokenEndpoint =
				env.getString("token_endpoint") != null
					? env.getString("token_endpoint")
					: env.getString("server", "token_endpoint");
			if (!tokenEndpoint) {
				throw this.error("Token endpoint not found");
			}

			const tokenEndpointTls = TLSTestValueExtractor.extractTlsFromUrl(tokenEndpoint);
			env.putObject("token_endpoint_tls", tokenEndpointTls);

			const userInfoEndpoint =
				env.getString("userinfo_endpoint") != null
					? env.getString("userinfo_endpoint")
					: env.getString("server", "userinfo_endpoint");
			let userInfoEndpointTls: JsonObject | null = null;
			if (userInfoEndpoint) {
				userInfoEndpointTls = TLSTestValueExtractor.extractTlsFromUrl(userInfoEndpoint);
				env.putObject("userinfo_endpoint_tls", userInfoEndpointTls);
			}

			const registrationEndpoint =
				env.getString("registration_endpoint") != null
					? env.getString("registration_endpoint")
					: env.getString("server", "registration_endpoint");
			let registrationEndpointTls: JsonObject | null = null;
			if (registrationEndpoint) {
				registrationEndpointTls = TLSTestValueExtractor.extractTlsFromUrl(registrationEndpoint);
				env.putObject("registration_endpoint_tls", registrationEndpointTls);
			}

			this.logSuccess(
				"Extracted TLS information from authorization server configuration",
				args(
					"authorization_endpoint",
					authorizationEndpointTls,
					"token_endpoint",
					tokenEndpointTls,
					"userinfo_endpoint",
					userInfoEndpointTls,
					"registration_endpoint",
					registrationEndpointTls,
				),
			);

			return env;
		} catch (e) {
			// Java: only MalformedURLException is caught here
			if (e instanceof ConditionError) {
				throw e;
			}
			throw this.error("URL not properly formed", e);
		}
	}
}
