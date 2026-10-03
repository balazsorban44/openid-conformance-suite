import {
	AbstractCondition,
	HttpClientException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CallDynamicRegistrationEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server", "dynamic_registration_request"] };
	static override post: EnvironmentRequirements = { required: ["dynamic_registration_endpoint_response"] };

	protected allowJsonParseFailure(): boolean {
		return false;
	}

	override async evaluate(env: Environment): Promise<Environment> {
		let registrationEndpoint: string | null = null;

		if (env.containsObject("mutual_tls_authentication")) {
			// for now, use the MTLS aliased endpoint if we have MTLS authentication available.
			// This is to cater for Brazil, where the DCR endpoint requires MTLS authentication.
			// It's not quite right for OIDC/CIBA cases if MTLS client authentication is in use -
			// the generic OAuth2 DCR endpoint shouldn't require MTLS.
			// I think here we could just call env.getString("server", "mtls_endpoint_aliases.registration_endpoint");
			// but https://gitlab.com/openid/conformance-suite/-/issues/914 is open to reconsider the overall
			// mechanism.
			registrationEndpoint = env.getString("registration_endpoint");
		}

		if (registrationEndpoint == null) {
			registrationEndpoint = env.getString("server", "registration_endpoint");
		}

		if (registrationEndpoint == null) {
			throw this.error("Couldn't find registration endpoint");
		}

		const requestObj = env.getObject("dynamic_registration_request") as JsonObject;

		const client = this.createHttpClient(env);
		try {
			// Treat all http status codes as 'not an error' - the HttpClient never throws due to the http
			// status code meaning the rest of our code can handle http status codes how it likes
			const headers = new Headers();

			headers.set("Accept", "application/json");
			headers.set("Accept-Charset", "utf-8");
			headers.set("Content-Type", "application/json");

			/*
			 * If there is an initial access token configured for the client include it in the authorization header.
			 *
			 * As per: https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration
			 */
			const initialAccessToken = env.getString("initial_access_token");
			if (initialAccessToken) {
				headers.set("Authorization", "Bearer " + initialAccessToken);
			}

			try {
				const response = await client.exchange({
					url: registrationEndpoint,
					method: "POST",
					headers,
					body: JSON.stringify(requestObj),
				});

				const responseInfo = this.convertJsonResponseForEnvironment(
					"dynamic registration",
					response,
					this.allowJsonParseFailure(),
				);

				env.putObject("dynamic_registration_endpoint_response", responseInfo);

				this.log("Parsed registration endpoint response", responseInfo);

				return env;
			} catch (e) {
				if (e instanceof HttpClientException) {
					return this.handleClientException(env, e);
				}
				throw e;
			}
		} finally {
			await client.close();
		}
	}

	protected handleClientException(env: Environment, e: HttpClientException): Environment {
		let msg = "Call to registration endpoint failed";
		// the HttpClientException message already carries the I/O error detail (Java: e.getCause().getMessage())
		const cause = e.cause;
		if (cause != null) {
			const detail =
				cause instanceof Error && cause.cause instanceof Error ? cause.cause.message : (cause as Error).message;
			msg += " - " + detail;
		}
		throw this.error(msg, e);
	}
}
