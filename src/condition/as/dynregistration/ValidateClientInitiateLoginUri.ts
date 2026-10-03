import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";

export class ValidateClientInitiateLoginUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		const client = env.getObject("client") as JsonObject;

		if (!("initiate_login_uri" in client)) {
			throw this.error("Client configuration does not contain required 'initiate_login_uri'");
		}

		const initiateLoginUri = client["initiate_login_uri"];
		const initiateLoginUriString = OIDFJSON.getString(initiateLoginUri);
		let url: URL;
		try {
			url = new URL(initiateLoginUriString);
		} catch {
			throw this.error("initiate_login_uri does not contain a valid URL", args("initiate_login_uri", initiateLoginUri));
		}

		if (url.protocol !== "https:") {
			throw this.error("initiate_login_uri does not use https", args("initiate_login_uri", initiateLoginUri));
		}

		// Java's URL.toString() returns the original external form, so log the original string
		this.logSuccess("valid initiate_login_uri", args("initiate_login_uri", initiateLoginUriString));

		return env;
	}
}
