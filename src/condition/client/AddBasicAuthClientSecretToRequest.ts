import {
	AbstractCondition,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

/** Equivalent of Java's URLEncoder.encode(s, UTF_8) (application/x-www-form-urlencoded) */
function urlEncode(s: string): string {
	return new URLSearchParams([["x", s]]).toString().substring(2);
}

export class AddBasicAuthClientSecretToRequest extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["request_headers", "client"] };
	static override post: EnvironmentRequirements = { required: ["request_headers"] };

	override evaluate(env: Environment): Environment {
		const id = env.getString("client", "client_id");

		if (id == null) {
			throw this.error("Client ID not found in configuration");
		}

		const secret = env.getString("client", "client_secret");

		if (secret == null) {
			throw this.error("Client secret not found in configuration");
		}

		const headers = env.getObject("request_headers") as JsonObject;

		const pw = Buffer.from(
			//application/x-www-form-urlencoded as per https://tools.ietf.org/html/rfc6749#section-2.3.1
			urlEncode(id) + ":" + urlEncode(secret),
		).toString("base64");

		headers["Authorization"] = "Basic " + pw;

		this.logSuccess("Added basic authorization header", headers);

		return env;
	}
}
