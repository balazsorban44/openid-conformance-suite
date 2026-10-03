/**
 * WebFinger (RFC 7033) for OpenID Provider Issuer Discovery (OIDCD-2) at the emulated OP: the RP asks
 * `/.well-known/webfinger?resource=...` on the issuer's host and gets the issuer as the
 * `http://openid.net/specs/connect/1.0/issuer` link. The resource names the test: `acct:<alias>.<test name>@<host>`
 * or `https://<host>/.../<alias>/<test name>`.
 */
import { block, condition } from "../suite/conditions.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { failTest, type EmulatedOp } from "./op.ts";

/** upstream: condition/as/CreateWebfingerResponse.java */
export function createWebfingerResponse(
	resource: string,
	issuer: string,
	...requirements: string[]
): Record<string, unknown> {
	const response = { subject: resource, links: [{ rel: "http://openid.net/specs/connect/1.0/issuer", href: issuer }] };
	condition("CreateWebfingerResponse", ...requirements).log("Created webfinger response", {
		webfinger_response: response,
	});
	return response;
}

/**
 * The webfinger request: the resource must name a running test (else 400 / 404 without touching the test), the
 * test must be this one, the module may require a resource syntax (`validateWebfingerResource`), then the response
 * links to `issuer` (upstream env "issuer", the issuer the configuration was generated with).
 *
 * upstream: runner/TestDispatcher.handleWellKnownWebFingerRequest, AbstractOIDCCClientTest.handleWebfingerRequest
 */
export async function handleWebfingerRequest(
	op: EmulatedOp,
	req: IncomingRequest,
	issuer: string,
): Promise<{ response: Response; webfinger: Record<string, unknown> | null }> {
	const resource = req.query_string_params["resource"];
	if (typeof resource !== "string") {
		// https://tools.ietf.org/html/rfc7033#section-4
		return { response: Response.json({ error: "resource parameter missing" }, { status: 400 }), webfinger: null };
	}
	const acct = /^acct:([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)@.*$/i.exec(resource);
	const match = acct ?? /^https?:\/\/.*\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)$/i.exec(resource);
	if (!match) {
		return { response: new Response(null, { status: 400 }), webfinger: null };
	}
	const resourcePrefix = acct ? "acct" : "https";
	const [, alias, requestedTestName] = match;
	// the test is found by the alias (or test id) its base url ends with
	const ownAlias = decodeURIComponent(op.baseUrl.substring(op.baseUrl.lastIndexOf("/") + 1));
	if (alias !== ownAlias) {
		return {
			response: Response.json(
				{ error: "no running test for test id '" + alias + "' from alias '" + alias + "'" },
				{ status: 404 },
			),
			webfinger: null,
		};
	}
	return block("Webfinger Request", () => {
		// this should not happen but just in case
		if (op.testName !== requestedTestName) {
			failTest(
				"Test name in webfinger request does not match current test name. " +
					"Requested=" +
					requestedTestName +
					" actual=" +
					op.testName,
			);
		}
		op.options.validateWebfingerResource?.(resourcePrefix);
		const webfinger = createWebfingerResponse(resource, issuer, "OIDCD-2");
		return { response: Response.json(webfinger), webfinger };
	});
}
