import assert from "node:assert/strict";
import { snapshot, test } from "node:test";
import { modelAndView } from "./views.ts";

// store the rendered HTML as is, so the snapshot file reads like the page
snapshot.setDefaultSnapshotSerializers([(v) => v]);

const nasty = `a<b>"c"&'d'</script>`;

const cases: [string, Parameters<typeof modelAndView>[0], Record<string, unknown>][] = [
	[
		"implicitCallback",
		"implicitCallback",
		{ implicitSubmitUrl: "https://suite/test/x/implicit/" + nasty, returnUrl: "/log-detail.html?log=x" },
	],
	[
		"formPostResponseMode",
		"formPostResponseMode",
		{
			formAction: "https://rp/cb?a=1&b=" + nasty,
			formParameters: { code: "c0de", state: nasty, num: 1, obj: { k: "v" } },
		},
	],
	["formPostResponseMode without parameters", "formPostResponseMode", { formAction: "https://rp/cb" }],
	["resultCaptured", "resultCaptured", { returnUrl: "/log-detail.html?log=" + nasty }],
	["resultCaptured without returnUrl", "resultCaptured", {}],
	[
		"checkSessionIFrame",
		"checkSessionIFrame",
		{ session_state: "state." + nasty, check_session_ajax_url: "https://suite/test/x/check_session_ajax?" + nasty },
	],
	["checkSessionIFrame without session_state", "checkSessionIFrame", { check_session_ajax_url: "https://suite/ajax" }],
	[
		"oidccFrontChannelLogout OP initiated",
		"oidccFrontChannelLogout",
		{
			post_logout_redirect_uri_redirect: "OPINIT",
			iframe_loaded_callback_url: "https://suite/loaded?" + nasty,
			rp_frontchannel_logout_uri: "https://rp/fcl?" + nasty,
		},
	],
	[
		"oidccFrontChannelLogout RP initiated",
		"oidccFrontChannelLogout",
		{
			post_logout_redirect_uri_redirect: "https://rp/post-logout?" + nasty,
			iframe_loaded_callback_url: "https://suite/loaded",
			rp_frontchannel_logout_uri: "https://rp/fcl",
		},
	],
	[
		"rpSessionIframe",
		"rpSessionIframe",
		{
			client_id: "client " + nasty,
			session_state: "ss.salt",
			issuer: "https://op/" + nasty,
			service_url: "https://suite/s",
		},
	],
	["rpSessionIframe empty model", "rpSessionIframe", {}],
	[
		"sessionVerify",
		"sessionVerify",
		{ check_session_iframe: "https://op/check?" + nasty, session_iframe_unchanged: "https://suite/rp_iframe" },
	],
	["sessionVerify without urls", "sessionVerify", { check_session_iframe: null }],
];

for (const [title, view, model] of cases) {
	test(`view ${title} renders unchanged`, async (t) => {
		const response = modelAndView(view, model);
		assert.equal(response.status, 200);
		assert.deepEqual(Object.fromEntries(response.headers), {
			"cache-control": "no-cache, no-store, must-revalidate",
			"content-type": "text/html;charset=UTF-8",
			pragma: "no-cache",
		});
		t.assert.snapshot(await response.text());
	});
}

test("modelAndView passes a status through", () => {
	assert.equal(modelAndView("resultCaptured", {}, 400).status, 400);
});
