import { AbstractCondition, type Environment } from "../../framework/index.ts";

export class UserInfoEndpointWithAccessTokenInBodyNotSupported extends AbstractCondition {
	override evaluate(_env: Environment): Environment {
		throw this.error(
			"The server returned a non-2xx HTTP response, and hence does not appear to support access tokens passed in the POST body.",
		);
	}
}
