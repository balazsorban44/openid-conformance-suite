import { args, type Environment } from "../../framework/index.ts";
import { AbstractCallProtectedResource } from "./AbstractCallProtectedResource.ts";

export abstract class AbstractCallProtectedResourceWithBearerToken extends AbstractCallProtectedResource {
	protected override getHeaders(env: Environment): Headers {
		const headers = super.getHeaders(env);

		const accessToken = env.getString("access_token", "value");
		if (!accessToken) {
			throw this.error("Access token not found");
		}

		const tokenType = env.getString("access_token", "type");
		if (!tokenType) {
			throw this.error("Token type not found");
		} else if (tokenType.toLowerCase() === "bearer" || tokenType.toLowerCase() === "dpop") {
			headers.set("Authorization", tokenType + " " + accessToken);
		} else {
			throw this.error("Access token is neither a bearer nor a dpop token", args("token_type", tokenType));
		}

		return headers;
	}
}
