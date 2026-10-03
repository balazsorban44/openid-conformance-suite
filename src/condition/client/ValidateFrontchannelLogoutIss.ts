import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";

export class ValidateFrontchannelLogoutIss extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: ["frontchannel_logout_request", "server"] };

	override evaluate(env: Environment): Environment {
		const issuer = env.getString("server", "issuer"); // to validate the issuer
		const issuerInRequest = env.getString("frontchannel_logout_request", "query_string_params.iss");

		if (!issuer) {
			throw this.error("Couldn't find issuer");
		}

		if (!issuerInRequest) {
			throw this.error("'iss' missing from frontchannel logout request");
		}

		if (issuer !== issuerInRequest) {
			throw this.error("Issuer mismatch", args("expected", issuer, "actual", issuerInRequest));
		}

		this.logSuccess("'iss' in frontchannel logout request matches server issuer");
		return env;
	}
}
