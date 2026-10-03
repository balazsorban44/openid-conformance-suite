import { escapeHtml, registerView } from "../views.ts";

// Port of templates/checkSessionIFrame.html
// Thymeleaf [[${x}]] text inlining (no th:inline="javascript") HTML-escapes the value -> escapeHtml().
// A model key that is not supplied (session_state is not passed by AbstractOIDCCClientLogoutTest) renders empty.
registerView("checkSessionIFrame", (model) => {
	const sessionState = escapeHtml(model["session_state"] ?? "");
	const checkSessionAjaxUrl = escapeHtml(model["check_session_ajax_url"] ?? "");
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
        Initial session_state: ${sessionState}
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
    var checkSessionUrl = '${checkSessionAjaxUrl}';
    var logCounter = 0;
    window.addEventListener("message", receiveMessage, false);
    function receiveMessage(event){
        console.log("check_session_iframe received message via postMessage");
        console.log(event);
        var splitData = event.data.split(' ');
        var clientIdInMessage = splitData[0];
        var splitStateAndSalt = splitData[1].split('.');
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
});
