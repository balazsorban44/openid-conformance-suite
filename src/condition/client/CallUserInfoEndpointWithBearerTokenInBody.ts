import type { Environment } from "../../framework/index.ts";
import type { HttpMethod } from "./AbstractCallProtectedResource.ts";
import { CallUserInfoEndpoint } from "./CallUserInfoEndpoint.ts";

export class CallUserInfoEndpointWithBearerTokenInBody extends CallUserInfoEndpoint {
	protected override getMethod(_env: Environment): HttpMethod {
		return "POST";
	}

	protected override getHeaders(_env: Environment): Headers {
		// Don't add an Authorization header
		return new Headers();
	}

	protected override getBody(env: Environment): URLSearchParams {
		const body = new URLSearchParams();
		body.append("access_token", this.getAccessToken(env));
		return body;
	}
}
