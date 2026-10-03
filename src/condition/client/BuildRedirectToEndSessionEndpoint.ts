import {
	AbstractCondition,
	args,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../framework/index.ts";

import { toUriString } from "../../util/UriComponentsBuilder.ts";

export class BuildRedirectToEndSessionEndpoint extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["end_session_endpoint_request", "server"] };
	static override post: EnvironmentRequirements = { strings: ["redirect_to_end_session_endpoint"] };

	override evaluate(env: Environment): Environment {
		const endSessionEndpointRequest = env.getObject("end_session_endpoint_request") as JsonObject;

		const endSessionEndpoint = env.getString("server", "end_session_endpoint");
		if (!endSessionEndpoint) {
			throw this.error("Couldn't find end_session endpoint");
		}

		// send a front channel request to start things off
		const queryParams: [string, string][] = [];

		for (const key of Object.keys(endSessionEndpointRequest)) {
			const element = endSessionEndpointRequest[key];
			queryParams.push([key, OIDFJSON.getString(element)]);
		}

		const redirectTo = toUriString(endSessionEndpoint, queryParams);

		this.logSuccess("Sending to end_session endpoint", args("redirect_to_end_session_endpoint", redirectTo));

		env.putString("redirect_to_end_session_endpoint", redirectTo);

		return env;
	}
}
