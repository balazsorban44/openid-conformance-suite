import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import type { EndpointResponse } from "../suite/http.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	createRPFrontChannelLogoutRequestUrl,
	ensureBackChannelLogoutEndpointResponseContainsCacheHeaders,
	escapeEcmaScript,
} from "./logout.ts";
import { generateSessionState } from "./session.ts";

const t = useTestLog();
const lastEntry = () => t.entries().at(-1);

describe("session_state", () => {
	test("is the salted hash of client_id, the redirect_uri's origin with its default port, and the OP browser state", () => {
		const data = generateSessionState("client 1", { redirect_uri: "HTTPS://RP.example/cb?x=1" });
		expect(data.origin).toBe("https://rp.example:443");
		const [hash, salt] = data.session_state.split(".");
		expect(salt).toBe(data.salt);
		const expected = createHash("sha256")
			.update(`client 1 https://rp.example:443 ${data.op_browser_state} ${data.salt}`)
			.digest("base64url");
		expect(hash).toBe(expected);
		expect(generateSessionState("c", { redirect_uri: "http://localhost:4000/cb" }).origin).toBe(
			"http://localhost:4000",
		);
	});
});

describe("front-channel logout request url", () => {
	const session = { sid: "s 1", session_state: "", op_browser_state: "", salt: "", client_id: "c", origin: "" };

	test("iss and sid are appended unencoded, before a fragment, only when the client requires the session", () => {
		const client = {
			client_id: "c",
			frontchannel_logout_uri: "https://rp.example/fc?a=b#frag",
			frontchannel_logout_session_required: true,
		};
		expect(createRPFrontChannelLogoutRequestUrl(client, "https://op/", session)).toBe(
			"https://rp.example/fc?a=b&iss=https://op/&sid=s 1#frag",
		);
		expect(
			createRPFrontChannelLogoutRequestUrl(
				{ client_id: "c", frontchannel_logout_uri: "https://rp/fc" },
				"https://op/",
				session,
			),
		).toBe("https://rp/fc");
	});

	test("the url is escaped for a JavaScript string like StringEscapeUtils.escapeEcmaScript", () => {
		expect(escapeEcmaScript(`https://rp/fc?sid=a'b"c\\é\n`)).toBe(`https:\\/\\/rp\\/fc?sid=a\\'b\\"c\\\\\\u00E9\\n`);
	});
});

describe("back-channel logout response cache headers", () => {
	const response = (cacheControl?: string | string[]): EndpointResponse => ({
		status: 200,
		endpoint_name: "backchannel logout",
		headers: cacheControl === undefined ? {} : { "cache-control": cacheControl },
		body: null,
	});

	test("no-store must be one of the cache-control directives, in any of the headers", () => {
		ensureBackChannelLogoutEndpointResponseContainsCacheHeaders(response(["no-cache", "private, no-store"]));
		expect(lastEntry()).toMatchObject({ result: "SUCCESS" });
		expect(() => ensureBackChannelLogoutEndpointResponseContainsCacheHeaders(response("no-store-x"))).toThrow(
			ConditionFailed,
		);
		expect(() => ensureBackChannelLogoutEndpointResponseContainsCacheHeaders(response())).toThrow(
			"RP backchannel_logout_uri response does not contain 'cache-control' header",
		);
	});
});
