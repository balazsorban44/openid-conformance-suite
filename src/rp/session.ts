/**
 * The emulated OP's login session with the RP's user agent (OpenID Connect Session Management 1.0): the
 * session_state it returns with the authorization response, the sid in the id_token, and the check_session_iframe
 * the RP loads to ask whether the session changed.
 *
 * The check_session_iframe page does not compute session_state itself: it passes the RP's postMessage to the
 * suite (get_session_state) and answers "unchanged" while the OP still has the session, "changed" after logout.
 *
 * upstream: openid/client/logout/AbstractOIDCCClientLogoutTest.java (handleCheckSessionIFrameRequest,
 * handleGetSessionStateViaAjaxRequest), templates/checkSessionIFrame.html
 */
import { createHash } from "node:crypto";
import { block, condition, type Condition } from "../suite/conditions.ts";
import { escapeHtml } from "../suite/log.ts";
import { randomAlphanumeric } from "../suite/random.ts";
import { htmlResponse } from "../suite/server.ts";
import { parseJavaURI, URISyntaxException } from "../util/jdk/uri.ts";
import type { AuthorizationParams } from "./authorization.ts";
import type { IdTokenClaims } from "./id-token.ts";
import { generateVSChar } from "./registration.ts";

/** upstream env "session_state_data" (GenerateSessionState) */
export interface SessionStateData {
	session_state: string;
	/** "this is actually a session id but the spec calls it OP browser state" */
	op_browser_state: string;
	salt: string;
	client_id: string;
	origin: string;
	sid: string;
}

/** The OP's session with the RP's user agent: created by the authorization request, removed by logout */
export interface LoginSession {
	/** upstream "session_state_data": null before the authorization request and after logout */
	data: SessionStateData | null;
	/** upstream receivedEndSessionRequest: the RP called the end_session_endpoint */
	endSessionRequestReceived: boolean;
}

/** The origin of the redirect_uri, with the default port made explicit (upstream GenerateSessionState.getOrigin) */
function originOf(c: Condition, redirectUri: string): string {
	try {
		const uri = parseJavaURI(redirectUri);
		// UPSTREAM: a null scheme/host throws (Java: NullPointerException)
		let origin = (uri.scheme as string).toLowerCase() + "://" + (uri.host as string).toLowerCase();
		if (uri.port === -1) {
			origin += "http" === uri.scheme?.toLowerCase() ? ":80" : ":443";
		} else {
			origin += ":" + uri.port;
		}
		return origin;
	} catch (e) {
		if (!(e instanceof URISyntaxException)) {
			throw e;
		}
		c.failure("Unable to extract origin from redirect_uri, invalid redirect_uri", { redirect_uri: redirectUri });
	}
}

/**
 * session_state = base64url(SHA-256(client_id + " " + origin + " " + op_browser_state + " " + salt)) + "." + salt,
 * plus a sid for the id_token / logout token. `clientId` is the registered client's (upstream reads env "client";
 * EnsureMatchingClientId made sure the request's client_id is the same).
 *
 * upstream: condition/as/logout/GenerateSessionState.java
 */
export function generateSessionState(
	clientId: string,
	params: AuthorizationParams,
	...requirements: string[]
): SessionStateData {
	const c: Condition = condition("GenerateSessionState", ...requirements);
	const salt = randomAlphanumeric(50);
	const opBrowserState = randomAlphanumeric(50);
	const origin = originOf(c, params["redirect_uri"] as string);
	const digest = createHash("sha256")
		.update(clientId + " " + origin + " " + opBrowserState + " " + salt, "utf8")
		.digest();
	const data: SessionStateData = {
		session_state: digest.toString("base64url") + "." + salt,
		op_browser_state: opBrowserState,
		salt,
		client_id: clientId,
		origin,
		sid: generateVSChar(20, 10, 5),
	};
	c.log("Generated session_state", { session_state_data: data });
	return data;
}

/** upstream: condition/as/logout/AddSessionStateToAuthorizationEndpointResponseParams.java */
export function addSessionStateToAuthorizationEndpointResponseParams(
	params: Record<string, string>,
	session: SessionStateData,
	...requirements: string[]
): void {
	params["session_state"] = session.session_state;
	condition("AddSessionStateToAuthorizationEndpointResponseParams", ...requirements).log(
		"Added session_state to authorization endpoint response params",
		{ authorization_endpoint_response_params: params },
	);
}

/** upstream: condition/as/logout/AddSidToIdTokenClaims.java */
export function addSidToIdTokenClaims(
	claims: IdTokenClaims,
	session: SessionStateData,
	...requirements: string[]
): void {
	claims["sid"] = session.sid;
	condition("AddSidToIdTokenClaims", ...requirements).success("Added sid to ID token claims", {
		id_token_claims: claims,
		sid: session.sid,
	});
}

/** upstream: condition/as/logout/LogoutByRemovingSessionState.java */
export function logoutByRemovingSessionState(session: LoginSession): void {
	session.data = null;
	condition("LogoutByRemovingSessionState").log("Removed session state");
}

/** upstream: condition/as/logout/LogCheckSessionIframeRequest.java */
export function logCheckSessionIframeRequest(): void {
	condition("LogCheckSessionIframeRequest").log("The client requested check_session_iframe");
}

/** upstream: condition/as/logout/LogGetSessionStateRequest.java */
export function logGetSessionStateRequest(data: SessionStateData | null): void {
	const c = condition("LogGetSessionStateRequest");
	if (data != null) {
		c.log("OP iframe received postMessage request from RP iframe", { returning_response: data });
	} else {
		c.log("OP iframe received postMessage request from RP iframe but the user is not logged in");
	}
}

// ---------------------------------------------------------------------------------------------------------------
// the endpoints

/**
 * The check_session_iframe page (upstream templates/checkSessionIFrame.html; upstream does not pass the model's
 * session_state, so the "Initial session_state" stays empty). It sends every message it receives to
 * `checkSessionAjaxUrl` and answers "unchanged" when the session_state in the message is the OP's, else "changed".
 */
export function checkSessionIframePage(checkSessionAjaxUrl: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDF Conformance: Check session iframe</title>
    <meta http-equiv="Cache-control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <style>
        #logsdiv div{
            border-bottom:1px solid #ddd;
            margin-top:0.2em;
            margin-bottom:0.4em;
        }
        body{
            font-family:sans-serif;
        }
    </style>
</head>
<body>
    <h1>Conformance Suite - OP check_session_iframe</h1>
    <div>
        Initial session_state:
    </div>


    <h3>Script Logs</h3>
    <div id="logsdiv">

    </div>

<script>
    /*
    PLEASE NOTE:
    This script is only intended for conformance testing purposes,
    and should not be used as a reference for real-life OP session management implementations.

    For the purposes for conformance testing, this script passes the received message to the
    suite via an ajax call and posts a changed/unchanged message based on the response it receives
    from the conformance suite.

    This is not how it should be implemented normally.
    */
    var checkSessionUrl = '${escapeHtml(checkSessionAjaxUrl)}';
    var logCounter = 0;
    window.addEventListener("message", receiveMessage, false);
    function receiveMessage(event){
        console.log("check_session_iframe received message via postMessage");
        console.log(event);
        // UPSTREAM: the template splits on the first space, but a client_id may itself contain spaces (the
        // suite's own RFC6749AppendixASyntaxUtils client ids do); session_state cannot, so split on the last one
        var lastSpace = event.data.lastIndexOf(' ');
        var clientIdInMessage = event.data.substring(0, lastSpace);
        var splitStateAndSalt = event.data.substring(lastSpace + 1).split('.');
        var sessionStateInMessage = splitStateAndSalt[0];
        var saltInMessage = splitStateAndSalt[1];

        const dataObj = {'receivedMessage':event.data, 'origin':event.origin};

        const urlData = Object.keys(dataObj).map(function(key) {
            return encodeURIComponent(key) + '=' + encodeURIComponent(dataObj[key]);
        }).join('&');

        let link = checkSessionUrl;
        if (link.indexOf('?') != -1) {
            link = link + '&' + urlData;
        }
        else {
            link = link + '?' + urlData;
        }

        var xhr = new XMLHttpRequest();
        xhr.open('GET', link, true);
        xhr.responseType = "json";
        xhr.onload = function () {
            addLog('Ajax call succeeded. Response:' + JSON.stringify(this.response));
            var opBrowserState = this.response.op_browser_state;
            var saltOnServer = this.response.salt;
            var originOnServer = this.response.origin;
            var sessionStateOnServer = this.response.session_state;

            if((sessionStateInMessage+'.'+saltInMessage) == sessionStateOnServer){
                addLog('Posting message: unchanged');
                event.source.postMessage('unchanged', event.origin);
            }
            else{
                addLog('Posting message: changed. Expected session state:"' + sessionStateOnServer + '" Actual:"' + sessionStateInMessage + '"');
                event.source.postMessage('changed', event.origin);
            }
        };
        xhr.onerror = function (error) {
            addLog('Error from ajax call to ' + checkSessionUrl);
            event.source.postMessage('error', event.origin);
        };
        xhr.send();
    }

    //shows logs on the page
    function addLog(msg){
        logCounter++;
        var logdiv = document.createElement("div");
        logdiv.innerText = logCounter + ': ' +  msg;
        document.getElementById('logsdiv').appendChild(logdiv);

    }
</script>

</body>
</html>`;
}

/**
 * The RP loads the check_session_iframe.
 *
 * upstream: AbstractOIDCCClientLogoutTest.handleCheckSessionIFrameRequest
 */
export async function handleCheckSessionIframeRequest(baseUrl: string): Promise<Response> {
	await block("check_session_iframe requested", () => logCheckSessionIframeRequest());
	return htmlResponse(checkSessionIframePage(baseUrl + "/get_session_state"));
}

/**
 * The check_session_iframe passes on a postMessage from the RP: the OP answers with its session_state_data (an
 * empty object after logout). `afterLogout` says whether the RP had already called the end_session_endpoint.
 *
 * upstream: AbstractOIDCCClientLogoutTest.handleGetSessionStateViaAjaxRequest
 */
export async function handleGetSessionStateRequest(
	session: LoginSession,
): Promise<{ response: Response; afterLogout: boolean }> {
	return block("Get session state - postMessage callback", () => {
		const afterLogout = session.endSessionRequestReceived;
		logGetSessionStateRequest(session.data);
		return { response: Response.json(session.data ?? {}), afterLogout };
	});
}
