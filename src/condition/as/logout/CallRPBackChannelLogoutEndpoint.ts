import {
	AbstractCondition,
	args,
	ex,
	HttpClientException,
	type Environment,
	type EnvironmentRequirements,
} from "../../../framework/index.ts";

export class CallRPBackChannelLogoutEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["server", "client"] };
	static override post: EnvironmentRequirements = { required: ["backchannel_logout_endpoint_response"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const formParameters = new URLSearchParams();
		formParameters.set("logout_token", env.getString("logout_token") as string);
		formParameters.set(
			"ignored_parameter",
			"The POST body MAY contain other values in addition to logout_token. " +
				"Values that are not understood by the implementation MUST be ignored.",
		);
		// Treat all http status codes as 'not an error' (HttpClient never throws due to the http status code),
		// so our code can handle http status codes how it likes
		const client = this.createRestTemplate(env);
		try {
			const logoutEndpointUri = env.getString("client", "backchannel_logout_uri") as string;
			const response = await client.exchange({
				url: logoutEndpointUri,
				method: "POST",
				headers: null,
				body: formParameters,
			});
			const responseInfo = this.convertResponseForEnvironment("backchannel logout", response);

			env.putObject("backchannel_logout_endpoint_response", responseInfo);

			this.logSuccess("Called backchannel_logout_uri", args("backchannel_logout_endpoint_response", responseInfo));
		} catch (e) {
			if (e instanceof HttpClientException) {
				return this.handleClientException(env, e);
			}
			throw e;
		} finally {
			await client.close();
		}
		return env;
	}

	protected handleClientException(_env: Environment, e: HttpClientException): Environment {
		throw this.error("RestClientException happened whilst calling logout endpoint", ex(e));
	}
}
