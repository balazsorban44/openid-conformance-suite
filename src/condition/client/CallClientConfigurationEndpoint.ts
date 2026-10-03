import {
	AbstractCondition,
	HttpClientException,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class CallClientConfigurationEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };
	static override post: EnvironmentRequirements = { required: ["registration_client_endpoint_response"] };

	protected allowJsonParseFailure(): boolean {
		return false;
	}

	override async evaluate(env: Environment): Promise<Environment> {
		const accessToken = env.getString("client", "registration_access_token");
		if (!accessToken) {
			throw this.error("Couldn't find registration_access_token in client object.");
		}

		const registrationClientUri = env.getString("client", "registration_client_uri");
		if (!registrationClientUri) {
			throw this.error("Couldn't find registration_client_uri in client object.");
		}

		const client = this.createHttpClient(env);
		try {
			// Treat all http status codes as 'not an error' - the HttpClient never throws due to the http
			// status code meaning the rest of our code can handle http status codes how it likes
			const headers = new Headers();
			headers.set("Accept", "application/json");
			headers.set("Accept-Charset", "utf-8");
			headers.set("Authorization", ["Bearer", accessToken].join(" "));

			let httpMethod: "GET" | "PUT" = "GET";
			let body: string | undefined;

			const requestBody = env.getObject("registration_client_endpoint_request_body");
			if (requestBody != null) {
				httpMethod = "PUT";
				headers.set("Content-Type", "application/json");
				body = JSON.stringify(requestBody);
			}

			try {
				const response = await client.exchange({
					url: registrationClientUri,
					method: httpMethod,
					headers,
					body,
				});
				const responseInfo: JsonObject = this.convertJsonResponseForEnvironment(
					"registration_client_uri",
					response,
					this.allowJsonParseFailure(),
				);

				env.putObject("registration_client_endpoint_response", responseInfo);

				this.logSuccess("Called registration_client_uri", responseInfo);
			} catch (e) {
				if (e instanceof HttpClientException) {
					return this.handleClientException(env, registrationClientUri, e);
				}
				throw e;
			}
		} finally {
			await client.close();
		}

		return env;
	}

	protected handleClientException(
		env: Environment,
		registrationClientUri: string,
		e: HttpClientException,
	): Environment {
		let msg = "Call to registration_client_uri " + registrationClientUri + " failed";
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
