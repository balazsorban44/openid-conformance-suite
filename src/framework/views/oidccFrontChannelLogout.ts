import { escapeHtml } from "./html.ts";

// Port of templates/oidccFrontChannelLogout.html
// Thymeleaf [[${x}]] text inlining (no th:inline="javascript") HTML-escapes the value -> escapeHtml().
// Note: rp_frontchannel_logout_uri is already JavaScript-escaped by the module (StringEscapeUtils.escapeEcmaScript).
export function oidccFrontChannelLogout(model: Record<string, unknown>): string {
	const redirect = String(model["post_logout_redirect_uri_redirect"] ?? "");
	const iframeLoadedCallbackUrl = escapeHtml(model["iframe_loaded_callback_url"] ?? "");
	const rpFrontchannelLogoutUri = escapeHtml(model["rp_frontchannel_logout_uri"] ?? "");
	const opInit = redirect === "OPINIT";
	const script = opInit
		? `    //OP init
    var iframe = document.createElement('iframe');
    iframe.onload = function(){
        let url = '${iframeLoadedCallbackUrl}';
        const urlData = 'loaded=true';

        if (url.indexOf('?') != -1) {
            url = url + '&' + urlData;
        }
        else {
            url = url + '?' + urlData;
        }

        var xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.onload = function () {
            document.getElementById('msgdiv').innerHTML = 'Logout uri loaded and test marked as finished. You can close this window and go back to the test window.';
        };
        xhr.onerror = function (event) {
            document.getElementById('msgdiv').innerHTML = 'Failed to mark test as finished! Please try again.';
        };
        xhr.send();
    }
    iframe.src = '${rpFrontchannelLogoutUri}';
    document.body.appendChild(iframe);`
		: `    //RP init
    var iframe = document.createElement('iframe');
    iframe.onload = function(){
        let url = '${iframeLoadedCallbackUrl}';
        const urlData = 'loaded=true';

        if (url.indexOf('?') != -1) {
            url = url + '&' + urlData;
        }
        else {
            url = url + '?' + urlData;
        }

        var xhr = new XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.onload = function () {
            document.getElementById('msgdiv').innerHTML = 'Logout uri loaded and test marked as finished. You will be redirected to post_logout_uri in 5 seconds.';
            setTimeout(function(){window.location.href='${escapeHtml(redirect)}';}, 5000);
        };
        xhr.onerror = function (event) {
            document.getElementById('msgdiv').innerHTML = 'Failed to mark test as finished! Please try again.';
        };
        xhr.send();
    }
    iframe.src = '${rpFrontchannelLogoutUri}';
    document.body.appendChild(iframe);`;
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDF Conformance: Check session iframe</title>
    <meta http-equiv="Cache-control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
</head>
<body>
    <h1>OP initiated front channel logout</h1>
    <div>
        RP frontchannel_logout_uri will be loaded below in an iframe
    </div>

    <div id="msgdiv"></div>
    <style>

        iframe{
            width:90%;
            height:400px;
        }
        #msgdiv{
            color:red;
            font-size:1.2em;
        }
    </style>

    <script>
${script}
    </script>

</body>
</html>`;
}
