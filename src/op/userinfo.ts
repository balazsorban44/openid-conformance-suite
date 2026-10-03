/**
 * The userinfo endpoint, the protected resource the OP tests call with the access token.
 *
 *   const url = discovery.setProtectedResourceUrlToUserInfoEndpoint(op.metadata);
 *   const res = await userinfo.callProtectedResource(url, tokens.accessToken);
 *   soft(() => ensureHttpStatusCodeIs200(res));
 */
import { condition, type Condition } from "../suite/conditions.ts";
import { endpointResponse, HttpError, request, type EndpointResponse } from "../suite/http.ts";
import type { AccessToken } from "./token.ts";

/**
 * Calls `url` with the access token (Authorization: <token type> <token>); any status is a response.
 *
 * upstream: condition/client/CallProtectedResource.java (AbstractCallProtectedResourceWithBearerToken)
 */
export async function callProtectedResource(
	url: string,
	accessToken: AccessToken,
	opts: { method?: "GET" | "POST"; headers?: Record<string, string>; body?: string | URLSearchParams } = {},
): Promise<EndpointResponse> {
	const c: Condition = condition("CallProtectedResource");
	if (!accessToken.value) {
		c.failure("Access token not found");
	}
	const type = accessToken.type;
	if (!type) {
		c.failure("Token type not found");
	}
	if (type.toLowerCase() !== "bearer" && type.toLowerCase() !== "dpop") {
		c.failure("Access token is neither a bearer nor a dpop token", { token_type: type });
	}
	if (!url) {
		c.failure("Missing Resource URL");
	}
	const method = opts.method ?? "GET";
	const headers: Record<string, string> = { Authorization: type + " " + accessToken.value, ...opts.headers };
	if (!Object.keys(headers).some((h) => h.toLowerCase() === "accept")) {
		headers["accept"] = "application/json";
	}
	if (method === "POST" && !Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) {
		// https://bitbucket.org/openid/connect/issues/1137/is-content-type-application-x-www-form
		headers["content-type"] = "application/x-www-form-urlencoded";
	}
	let res;
	try {
		res = await request(c.name, { url, method, headers, body: opts.body ?? null });
	} catch (e) {
		if (e instanceof HttpError) {
			const cause = e.cause instanceof Error ? e.cause.message : null;
			c.failureFrom("Call to protected resource " + url + " failed" + (cause ? " - " + cause : ""), e);
		}
		throw e;
	}
	const response = endpointResponse("resource", res);
	const { body_json: _json, ...logged } = response;
	c.success("Got a response from the resource endpoint", logged);
	return response;
}
