import { type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { AbstractExtractJWT } from "../AbstractExtractJWT.ts";

export class ExtractLogoutTokenFromBackchannelLogoutRequest extends AbstractExtractJWT {
	static override pre: EnvironmentRequirements = { required: ["backchannel_logout_request"] };
	static override post: EnvironmentRequirements = { required: ["logout_token"] };

	override async evaluate(env: Environment): Promise<Environment> {
		return this.extractJWT(env, "backchannel_logout_request", "body_form_params.logout_token", "logout_token");
	}
}
