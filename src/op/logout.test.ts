import { afterEach, beforeEach, describe, expect, test } from "vitest";
import type { Browser } from "../suite/browser.ts";
import { startServer, type TestServer } from "../suite/server.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	redirectToEndSessionEndpointAndWaitForLogoutRequest,
	redirectToEndSessionEndpointExpectingNoRedirect,
} from "./logout.ts";
import type { Op } from "./op.ts";

const t = useTestLog("oidcc-backchannel-rp-initiated-logout");
let server: TestServer;

beforeEach(async () => {
	server = await startServer({ log: t.log, testName: "oidcc-backchannel-rp-initiated-logout" });
});
afterEach(() => server.close());

/** An OP whose "browser" makes the given requests to the suite in order, as the OP's logout would */
function opWithBrowser(requests: { path: string; init?: RequestInit }[], opts: { thenWait?: boolean } = {}): Op {
	const browser: Browser = {
		visited: [],
		async visit() {
			for (const r of requests) {
				await fetch(server.baseUrl + "/" + r.path, r.init);
			}
			if (opts.thenWait) {
				// the automation keeps waiting for the page it expected (it times out later)
				await new Promise((resolve) => setTimeout(resolve, 2000));
			}
		},
	};
	return { server, browser, testId: t.log.testId } as unknown as Op;
}

function moduleMessages(): unknown[] {
	return t
		.entries()
		.filter(
			(e) => e.src === "oidcc-backchannel-rp-initiated-logout" && e["http"] !== "incoming" && e["http"] !== "outgoing",
		)
		.map((e) => e["msg"]);
}

describe("redirectToEndSessionEndpointAndWaitForLogoutRequest", () => {
	test("the back-channel request first: waits for the redirect and returns both", async () => {
		const op = opWithBrowser([
			{
				path: "backchannel_logout",
				init: {
					method: "POST",
					headers: { "content-type": "application/x-www-form-urlencoded" },
					body: "logout_token=x.y.z",
				},
			},
			{ path: "post_logout_redirect?state=s1" },
		]);
		const received = await redirectToEndSessionEndpointAndWaitForLogoutRequest(
			op,
			"https://op.example/end",
			"backchannel",
		);
		expect(received.logoutRequest.body_form_params).toEqual({ logout_token: "x.y.z" });
		expect(received.postLogoutRedirect.query_string_params).toEqual({ state: "s1" });
		expect(moduleMessages()).toEqual([
			"Redirecting to end session endpoint",
			"Received backchannel request; waiting for front channel redirect",
		]);
	});

	test("the redirect first: says it waits for the front-channel request", async () => {
		const op = opWithBrowser([{ path: "post_logout_redirect" }, { path: "frontchannel_logout?iss=i&sid=s" }]);
		const received = await redirectToEndSessionEndpointAndWaitForLogoutRequest(
			op,
			"https://op.example/end",
			"frontchannel",
		);
		expect(received.logoutRequest.query_string_params).toEqual({ iss: "i", sid: "s" });
		expect(moduleMessages()).toEqual([
			"Redirecting to end session endpoint",
			"Received front channel redirect; waiting for front channel request",
		]);
	});
});

describe("redirectToEndSessionEndpointExpectingNoRedirect", () => {
	test("resolves when the browser automation is done and the OP did not redirect back", async () => {
		await redirectToEndSessionEndpointExpectingNoRedirect(opWithBrowser([]), "https://op.example/end", "p1", "no!");
		expect(moduleMessages()).toEqual(["Redirecting to end session endpoint"]);
	});

	test("fails with the module's message when the OP redirects to the post_logout_redirect_uri", async () => {
		const op = opWithBrowser([{ path: "post_logout_redirect?state=s1" }], { thenWait: true });
		await expect(
			redirectToEndSessionEndpointExpectingNoRedirect(
				op,
				"https://op.example/end",
				"p1",
				"OP has incorrectly called it",
			),
		).rejects.toThrow("OP has incorrectly called it");
	});
});
