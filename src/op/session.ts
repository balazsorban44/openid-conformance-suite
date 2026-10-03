/**
 * OpenID Connect Session Management 1.0: the session_state of the authorization response and the OP's
 * check_session_iframe, asked by the suite's own RP iframe whether the session changed.
 *
 *   const sessionState = session.extractSessionStateFromAuthorizationResponse(response, "OIDCSM-2");
 *   const result = await session.checkSessionState(op, client.client, sessionState, "first");
 *   soft(() => session.checkSessionResultIsUnchanged(result, "OIDCSM-3.1"));
 *
 * The suite's pages (below its base url): session_verify holds the OP's check_session_iframe and the suite's
 * rp_session_iframe; the RP iframe posts "<client_id> <session_state>" to the OP's iframe and sends the browser to
 * session_result?state=<answer> (the second check uses the second_* paths).
 */
import { condition, logModule, type Condition } from "../suite/conditions.ts";
import { escapeHtml } from "../suite/log.ts";
import { htmlResponse, type IncomingRequest } from "../suite/server.ts";
import type { AuthorizationResponse } from "./authorization.ts";
import { resultCapturedPage } from "./logout.ts";
import type { Op } from "./op.ts";
import type { Client } from "./registration.ts";

/** upstream: condition/client/ExtractSessionStateFromAuthorizationResponse.java */
export function extractSessionStateFromAuthorizationResponse(
	response: AuthorizationResponse,
	...requirements: string[]
): string {
	const c: Condition = condition("ExtractSessionStateFromAuthorizationResponse", ...requirements);
	const sessionState = response.params["session_state"];
	if (typeof sessionState !== "string" || !sessionState) {
		c.failure("Couldn't find session_state in authorization_endpoint_response");
	}
	c.success("Found session_state", { session_state: sessionState });
	return sessionState;
}

/** th:src: an escaped src attribute, omitted for null */
function srcAttribute(v: string | null): string {
	return v == null ? "" : ` src="${escapeHtml(v)}"`;
}

/**
 * upstream templates/sessionVerify.html: the OP's check_session_iframe and the suite's RP iframe (Thymeleaf omits
 * a null src attribute)
 */
export function sessionVerifyPage(checkSessionIframe: string | null, rpSessionIframe: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <title>OIDF Conformance Suite: Session verification</title>
</head>
<body>

<h1>Session verification</h1>
<h2>Checking that the session hasn't changed!</h2>
<p>If you see this frame for more than a few seconds something has gone wrong.</p>
<iframe id="op_iframe"${srcAttribute(checkSessionIframe)} hidden></iframe>
<iframe id="rp_iframe"${srcAttribute(rpSessionIframe)} hidden></iframe>

</body>
</html>`;
}

/**
 * upstream templates/rpSessionIframe.html: posts "<client_id> <session_state>" to the OP's iframe and sends the
 * page to `serviceUrl?state=<answer>` once the OP's iframe answers (Thymeleaf text inlining HTML-escapes the values)
 */
export function rpSessionIframePage(
	clientId: string,
	sessionState: string,
	issuer: string,
	serviceUrl: string,
): string {
	return `<!DOCTYPE html>
<html lang="en">
<head lang="en">
    <meta charset="UTF-8">
    <title></title>
</head>
<body>

<script type="application/javascript">
    var client_id = "${escapeHtml(clientId)}";
    var session_state = "${escapeHtml(sessionState)}";
    console.log("RP session state: " + session_state);
    var issuer = "${escapeHtml(issuer)}";
    console.log("issuer: " + issuer);
    var targetOrigin = new URL(issuer).origin;

    var mes = client_id + " " + session_state;

    window.addEventListener("message", receiveMessage, false);

    function checkSession() {
        console.log("checkSession started")
        var win = window.parent.document.getElementById("op_iframe").contentWindow;
        win.postMessage(mes, "*");
    }

    function receiveMessage(e) {
        // when using browser automation, the log statements here can be viewed by enabling browser_verbose
        console.log("receiveMessage: origin: " + e.origin + " expected: " + targetOrigin);
        if (e.origin !== targetOrigin) {
            console.log("origin & targetOrigin mismatch");
            return;
        }
        console.log("setting window.parent.window.location.href to ${escapeHtml(serviceUrl)}?state="+e.data);
        window.parent.window.location.href = "${escapeHtml(serviceUrl)}" + "?state=" + e.data;
    }
    setTimeout(checkSession, 500);
</script>

</body>
</html>`;
}

/**
 * Sends the browser to the suite's session check page and resolves with the request to session_result, whose
 * `state` query parameter is the OP's check_session_iframe answer ("unchanged", "changed" or "error"). `which`
 * selects the first (before the logout) or the second (after it) set of the suite's paths.
 *
 * upstream: OIDCCSessionManagementRpInitiatedLogout.checkSessionState + handleSessionVerify / handleRpSessionIframe /
 * handleSessionResult
 */
export async function checkSessionState(
	op: Op,
	client: Client,
	sessionState: string,
	which: "first" | "second",
): Promise<IncomingRequest> {
	const prefix = which === "first" ? "" : "second_";
	const redirectTo = op.baseUrl + "/" + prefix + "session_verify";
	logModule({ msg: "Redirecting to our session check page", redirect_to: redirectTo, http: "redirect" });
	const checkSessionIframe = op.metadata["check_session_iframe"];
	const [, , result] = await Promise.all([
		op.server.waitFor(prefix + "session_verify", () =>
			htmlResponse(
				sessionVerifyPage(
					typeof checkSessionIframe === "string" ? checkSessionIframe : null,
					op.baseUrl + "/" + prefix + "rp_session_iframe",
				),
			),
		),
		op.server.waitFor(prefix + "rp_session_iframe", () =>
			htmlResponse(
				rpSessionIframePage(
					client.client_id,
					sessionState,
					String(op.metadata.issuer),
					op.baseUrl + "/" + prefix + "session_result",
				),
			),
		),
		op.server.waitFor(prefix + "session_result", htmlResponse(resultCapturedPage(op.testId))),
		op.browser.visit(redirectTo),
	]);
	return result;
}

function sessionResultState(result: IncomingRequest): string | null {
	const state = result.query_string_params["state"];
	return typeof state === "string" ? state : null;
}

/** upstream: condition/client/CheckSessionResultIsUnchanged.java */
export function checkSessionResultIsUnchanged(result: IncomingRequest, ...requirements: string[]): void {
	checkSessionResult(condition("CheckSessionResultIsUnchanged", ...requirements), result, "unchanged");
}

/** upstream: condition/client/CheckSecondSessionResultIsChanged.java */
export function checkSecondSessionResultIsChanged(result: IncomingRequest, ...requirements: string[]): void {
	checkSessionResult(condition("CheckSecondSessionResultIsChanged", ...requirements), result, "changed");
}

function checkSessionResult(c: Condition, result: IncomingRequest, expected: string): void {
	const state = sessionResultState(result);
	if (state == null) {
		c.failure("state not present in the result from our iframe; this might be a bug in the test.");
	}
	if (state !== expected) {
		c.failure("state from the OP's check_session_iframe does not have the expected value.", {
			actual: state,
			expected,
		});
	}
	c.success("state from the OP's check_session_iframe is '" + expected + "' as expected.");
}
