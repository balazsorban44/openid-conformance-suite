import {
	AbstractCondition,
	args,
	HttpClientException,
	type Environment,
	type EnvironmentRequirements,
} from "../../framework/index.ts";

export class UnregisterDynamicallyRegisteredClient extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override async evaluate(env: Environment): Promise<Environment> {
		const accessToken = env.getString("client", "registration_access_token");
		if (!accessToken) {
			this.log("Couldn't find registration_access_token.");
			return env;
		}

		const registrationClientUri = env.getString("client", "registration_client_uri");
		if (!registrationClientUri) {
			this.log("Couldn't find registration_client_uri.");
			return env;
		}

		const client = this.createHttpClient(env);
		try {
			const headers = new Headers();
			headers.set("accept", "application/json");
			headers.set("Authorization", "Bearer " + accessToken);

			try {
				const response = await client.exchange({
					url: registrationClientUri,
					method: "DELETE",
					headers,
				});
				if (response.status >= 400) {
					// Java: RestTemplate throws RestClientResponseException on 4xx/5xx
					throw this.error(
						"Error when calling registration_client_uri",
						args("code", response.status, "status", response.statusText, "body", response.body ?? ""),
					);
				}
				if (response.status !== 204) {
					throw this.error(
						"registration_client_uri returned a http status code other than 204 No Content",
						args("code", response.status),
					);
				}
			} catch (e) {
				if (e instanceof HttpClientException) {
					const msg = "Call to registration client uri " + registrationClientUri + " failed - " + e.message;
					throw this.error(msg, e);
				}
				throw e;
			}
		} finally {
			await client.close();
		}

		this.logSuccess("Client successfully unregistered");
		return env;
	}
}
