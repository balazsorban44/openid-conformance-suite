import type { JsonObject } from "../../framework/index.ts";
import { BuildPlainRedirectToAuthorizationEndpoint } from "./BuildPlainRedirectToAuthorizationEndpoint.ts";

/**
 * Same as {@link BuildPlainRedirectToAuthorizationEndpoint} but sorts parameters in
 * reverse alphabetical order, to test that implementations handle different parameter orderings.
 */
export class BuildPlainRedirectToAuthorizationEndpointReorderedParams extends BuildPlainRedirectToAuthorizationEndpoint {
	protected override getParameterOrder(authorizationEndpointRequest: JsonObject): string[] {
		const keys = Object.keys(authorizationEndpointRequest);
		keys.sort((a, b) => (a < b ? 1 : a > b ? -1 : 0));
		return keys;
	}
}
