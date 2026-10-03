import { escapeHtml } from "./html.ts";

// Port of templates/rpSessionIframe.html
// Thymeleaf [[${x}]] text inlining (no th:inline="javascript") HTML-escapes the value -> escapeHtml()
export function rpSessionIframe(model: Record<string, unknown>): string {
	const clientId = escapeHtml(model["client_id"] ?? "");
	const sessionState = escapeHtml(model["session_state"] ?? "");
	const issuer = escapeHtml(model["issuer"] ?? "");
	const serviceUrl = escapeHtml(model["service_url"] ?? "");
	return `<!DOCTYPE html>
<html lang="en">
<head lang="en">
    <meta charset="UTF-8">
    <title></title>
</head>
<body>

<script type="application/javascript">
    var client_id = "${clientId}";
    var session_state = "${sessionState}";
    console.log("RP session state: " + session_state);
    var issuer = "${issuer}";
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
        // when using browser automation, the log statements here can be viewed in the frontend by enabling
        // browser_verbose as per https://gitlab.com/openid/conformance-suite/-/wikis/Design/BrowserControl
        console.log("receiveMessage: origin: " + e.origin + " expected: " + targetOrigin);
        if (e.origin !== targetOrigin) {
            console.log("origin & targetOrigin mismatch");
            return;
        }
        console.log("setting window.parent.window.location.href to ${serviceUrl}?state="+e.data);
        window.parent.window.location.href = "${serviceUrl}" + "?state=" + e.data;
    }
    setTimeout(checkSession, 500);
</script>

</body>
</html>`;
}
