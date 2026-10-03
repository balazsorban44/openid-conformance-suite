import {
	AbstractCondition,
	args,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

export class ExtractClientCredentialsFromBasicAuthorizationHeader extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["token_endpoint_request"] };
	static override post: EnvironmentRequirements = { required: ["client_authentication"] };

	override evaluate(env: Environment): Environment {
		if (env.containsObject("client_authentication")) {
			throw this.error("Found existing client authentication");
		}

		const auth = env.getString("token_endpoint_request", "headers.authorization");

		if (!auth) {
			throw this.error(
				"This test expected the client to perform client_secret_basic client authorization, but the incoming http request does not contain an authorization header",
			);
		}

		if (!auth.toLowerCase().startsWith("basic")) {
			throw this.error("Not a basic authorization header", args("auth", auth));
		}

		// parse the HTTP Basic Auth
		const encoded = auth.substring("Basic ".length); // strip off the "Basic " prefix first though
		if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
			// Java: Base64.getDecoder().decode() throws IllegalArgumentException
			throw new Error("Illegal base64 character");
		}
		const decoded = Buffer.from(encoded, "base64").toString("utf8"); // base64 decode

		const parts = decoded.split(":"); // split the results at a colon to get username:password (in our case, clientId:clientSecret)

		if (parts.length !== 2) {
			// we don't have two parts
			throw this.error("Unexpected number of parts to authorization header", args("basic_auth", parts));
		}

		// Java: URLDecoder.decode(s, UTF_8) - form decoding, '+' is a space
		const clientId = decodeURIComponent(parts[0].replace(/\+/g, " "));
		const clientSecret = decodeURIComponent(parts[1].replace(/\+/g, " "));

		const clientAuthentication: JsonObject = {};
		clientAuthentication["client_id"] = clientId;
		clientAuthentication["client_secret"] = clientSecret;
		clientAuthentication["method"] = "client_secret_basic";

		env.putObject("client_authentication", clientAuthentication);

		this.logSuccess("Extracted client authentication", clientAuthentication);

		return env;
	}
}
