import {
	args,
	jsonArrayContains,
	OIDFJSON,
	type Environment,
	type EnvironmentRequirements,
	type JsonObject,
} from "../../../framework/index.ts";
import { AbstractClientValidationCondition } from "./AbstractClientValidationCondition.ts";

/**
 * grant_types
 * OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring
 * that it will restrict itself to using. The Grant Type values used by OpenID Connect are:
 * 		authorization_code: The Authorization Code Grant Type described in OAuth 2.0 Section 4.1.
 * 		implicit: The Implicit Grant Type described in OAuth 2.0 Section 4.2.
 * 		refresh_token: The Refresh Token Grant Type described in OAuth 2.0 Section 6.
 * The following table lists the correspondence between response_type values that the Client will use
 * and grant_type values that MUST be included in the registered grant_types list:
 * 		code: authorization_code
 * 		id_token: implicit
 * 		token id_token: implicit
 * 		code id_token: authorization_code, implicit
 * 		code token: authorization_code, implicit
 * 		code token id_token: authorization_code, implicit
 * If omitted, the default is that the Client will use only the authorization_code Grant Type.
 *
 * NOTE: When grant_types is set but EMPTY we do NOT default to authorization_code.
 * It will default to authorization_code when grant_types is not included at all.
 */
export class ValidateClientGrantTypes extends AbstractClientValidationCondition {
	static override pre: EnvironmentRequirements = { required: ["client"] };

	override evaluate(env: Environment): Environment {
		this.client = env.getObject("client") as JsonObject;

		const grantTypes = this.getGrantTypes();
		const responseTypes = this.getResponseTypes();

		let needImplicit = false;
		let needAuthorizationCode = false;
		for (const responseTypeElement of responseTypes) {
			const responseTypeAsSet = new Set<string>();
			for (const s of OIDFJSON.getString(responseTypeElement).split(" ")) {
				responseTypeAsSet.add(s);
			}
			if (responseTypeAsSet.has("code")) {
				needAuthorizationCode = true;
			}
			if (responseTypeAsSet.has("token") || responseTypeAsSet.has("id_token")) {
				needImplicit = true;
			}
		}

		const authorizationCodeJsonElement = "authorization_code";
		const implicitJsonElement = "implicit";

		if (needAuthorizationCode && !jsonArrayContains(grantTypes, authorizationCodeJsonElement)) {
			throw this.error(
				"response_types require the use of authorization_code grant_type",
				args("grant_types", grantTypes, "response_types", responseTypes),
			);
		}
		if (needImplicit && !jsonArrayContains(grantTypes, implicitJsonElement)) {
			throw this.error(
				"response_types require the use of implicit grant_type",
				args("grant_types", grantTypes, "response_types", responseTypes),
			);
		}

		this.logSuccess(
			"grant_types match response_types",
			args("grant_types", grantTypes, "response_types", responseTypes),
		);
		return env;
	}
}
