import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class CreateBackchannelLogoutUri extends AbstractCondition {
	static override pre: EnvironmentRequirements = { strings: ["base_url"] };
	static override post: EnvironmentRequirements = { strings: ["backchannel_logout_uri"] };

	override evaluate(env: Environment): Environment {
		let baseUrl = env.getString("base_url") as string;

		if (baseUrl === "") {
			throw this.error("Base URL is empty");
		}

		const externalUrlOverride = env.getString("external_url_override");
		if (externalUrlOverride) {
			baseUrl = externalUrlOverride;
		}

		// calculate the redirect URI based on our given base URL
		// the python suite included entity_id in the query string here originally, but this was removed in
		// https://github.com/rohe/oidctest/commit/2c5b8192105d1176eeaf29108fae152b66bcf41c I believe due to
		// https://github.com/openid-certification/oidctest/issues/224
		const backchannelLogoutUri = baseUrl + "/backchannel_logout";
		env.putString("backchannel_logout_uri", backchannelLogoutUri);

		this.logSuccess("Created backchannel_logout_uri URI", args("backchannel_logout_uri", backchannelLogoutUri));

		return env;
	}
}
