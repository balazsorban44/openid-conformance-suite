import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../../framework/index.ts";

export class CreateRPFrontChannelLogoutRequestUrl extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["client", "session_state_data"] };
	static override post: EnvironmentRequirements = { strings: ["rp_frontchannel_logout_uri_request_url"] };

	override evaluate(env: Environment): Environment {
		const frontchannelLogoutUri = env.getString("client", "frontchannel_logout_uri");
		const sessionRequired = env.getBoolean("client", "frontchannel_logout_session_required");

		if (frontchannelLogoutUri == null || frontchannelLogoutUri === "") {
			throw this.error("frontchannel_logout_uri is not defined for the client");
		}

		// UriComponentsBuilder.fromUriString(frontchannelLogoutUri) ... build().toUriString():
		// the components are not encoded, the new query params are appended to the existing query (if any)
		// and placed before the fragment (if any)
		const queryParams: string[] = [];

		if (sessionRequired != null && sessionRequired) {
			const iss = env.getString("issuer");
			const sid = env.getString("session_state_data", "sid");
			queryParams.push(iss == null ? "iss" : "iss=" + iss);
			queryParams.push(sid == null ? "sid" : "sid=" + sid);
		}

		let url = frontchannelLogoutUri;
		if (queryParams.length > 0) {
			const hashIndex = url.indexOf("#");
			const fragment = hashIndex === -1 ? "" : url.substring(hashIndex);
			let base = hashIndex === -1 ? url : url.substring(0, hashIndex);
			base += (base.includes("?") ? "&" : "?") + queryParams.join("&");
			url = base + fragment;
		}
		this.log("Created frontchannel_logout_uri request url", args("url", url));
		env.putString("rp_frontchannel_logout_uri_request_url", url);
		return env;
	}
}
