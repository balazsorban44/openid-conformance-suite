import { AbstractCondition, args, type Environment, type EnvironmentRequirements } from "../../framework/index.ts";
import { CreateEffectiveAuthorizationRequestParameters } from "./CreateEffectiveAuthorizationRequestParameters.ts";

export class ExtractRequestedScopes extends AbstractCondition {
	static override pre: EnvironmentRequirements = { required: [CreateEffectiveAuthorizationRequestParameters.ENV_KEY] };
	static override post: EnvironmentRequirements = { strings: ["request_scopes_contain_openid"] };

	override evaluate(env: Environment): Environment {
		const scope = env.getString(
			CreateEffectiveAuthorizationRequestParameters.ENV_KEY,
			CreateEffectiveAuthorizationRequestParameters.SCOPE,
		);

		if (!scope) {
			throw this.error("Missing scope parameter");
		} else {
			this.logSuccess("Requested scopes", args("scope", scope));

			let openidScopeRequested = "no";
			const scopes = scope.split(" ");
			for (const scopePiece of scopes) {
				if ("openid" === scopePiece) {
					openidScopeRequested = "yes";
					break;
				}
			}

			env.putString("request_scopes_contain_openid", openidScopeRequested);
			env.putString("scope", scope);

			return env;
		}
	}
}
