import { footer, jsLiteral } from "./html.ts";

// Port of templates/implicitCallback.html
export function implicitCallback(model: Record<string, unknown>): string {
	const implicitSubmitUrl = model["implicitSubmitUrl"];
	const returnUrl = model["returnUrl"];
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDF Conformance: Processing Implicit Callback</title>
</head>
<body>
    <div>
        <h1>Please wait...</h1>
        <h2>Processing response from authorization server</h2>
        <p id="complete" class="collapse">The response has been sent to the server for processing. You may return to <a href="">the test results page.</a></p>
    </div>
    ${footer}
    <script type="text/javascript">
        var submitComplete = false;
        function assumeComplete() {
            if (submitComplete) {
                return;
            }
            console.log("assumeComplete workaround for https://gitlab.com/openid/conformance-suite/-/issues/766 activated - assuming post has completed as 5 seconds have elapsed")
            document.getElementById('complete').insertAdjacentHTML('beforeend', '<span id="submission_complete" hidden></span>');
        }

        document.addEventListener("DOMContentLoaded", () => {
            var hash = window.location.hash;
            var returnUrl = ${jsLiteral(returnUrl)};
            var timeoutId = setTimeout(function(){ assumeComplete(); }, 5000);

            function createxhr() {
                var xhr = new XMLHttpRequest();
                xhr.open('POST', ${jsLiteral(implicitSubmitUrl)}, true);
                xhr.setRequestHeader('Content-type', 'text/plain');
                xhr.onload = function () {
                    submitComplete = true;
                    document.querySelector('#complete a').setAttribute("href", returnUrl);
                    document.getElementById('complete').classList.add('show');
                    document.getElementById('complete').insertAdjacentHTML('beforeend', '<span id="submission_complete" hidden></span>');
                };
                xhr.onabort = function () { console.log("implicit submit abort") };
                xhr.ontimeout = function () { console.log("implicit submit timeout") };
                return xhr;
            }

            var xhr = createxhr();
            xhr.onerror = function () {
                console.log("implicit submit error (trying again in 2 seconds): " + xhr.status + " " + xhr.responseText);
                clearTimeout(timeoutId);
                timeoutId = setTimeout(function(){ assumeComplete(); }, 5000);
                setTimeout(function() {
                    var newxhr = createxhr();
                    newxhr.onerror = function () {
                        console.log("second implicit submit error: " + xhr.status + " " + xhr.responseText);
                    }
                    newxhr.send(hash);
                }, 2000);
            };
            xhr.send(hash);
        });
    </script>
</body>
</html>`;
}
