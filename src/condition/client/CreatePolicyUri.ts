import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreatePolicyUri extends AbstractCondition {
	// As per https://openid.net/specs/openid-connect-registration-1_0.html#Impersonation
	// "The Authorization Server SHOULD check to see if the logo_uri and policy_uri have the same host as the hosts defined in the array of redirect_uris."
	// so we generate a url that exists on the conformance server, and the login page is one of the few unauthenticated
	// pages we currently have
	private static readonly LOGO_PATH = "/login.html";

	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["policy_uri"] };

	override evaluate(env: Environment): Environment {
		let policyUri: string;
		try {
			const baseUri = new URL(env.getString("base_url") as string);
			// new URI(scheme, null, host, port, path, null, null)
			policyUri =
				baseUri.protocol +
				"//" +
				baseUri.hostname +
				(baseUri.port !== "" ? ":" + baseUri.port : "") +
				CreatePolicyUri.LOGO_PATH;
		} catch (e) {
			// UPSTREAM: message says "logo URI" although this condition generates the policy URI
			throw this.error("Failed to generate logo URI", e);
		}

		env.putString("policy_uri", policyUri);

		this.log("Generated policy URI", args("policy_uri", policyUri));

		return env;
	}
}
