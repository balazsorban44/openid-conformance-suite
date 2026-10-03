import type { JsonObject, JsonValue } from "./json.ts";

/**
 * HTTP response helpers for test modules. Java modules return ResponseEntity / ModelAndView / RedirectView;
 * ported modules return a web `Response`.
 *
 *   new ResponseEntity<>(obj, HttpStatus.OK)              -> jsonResponse(obj, 200)
 *   new ResponseEntity<>(obj, headers, HttpStatus.OK)     -> jsonResponse(obj, 200, headers)
 *   new ResponseEntity<Object>("", HttpStatus.NO_CONTENT) -> noContent()
 *   new RedirectView(url, false, false, false)            -> redirectView(url)
 *   new ModelAndView("formPostResponseMode", model)       -> modelAndView("formPostResponseMode", model)
 */

export type HeadersInit = Headers | Record<string, string> | [string, string][];

export type ViewRenderer = (model: Record<string, unknown>) => string;

const views = new Map<string, ViewRenderer>();

/** Register a view template (port of a Thymeleaf template under src/main/resources/templates) */
export function registerView(name: string, renderer: ViewRenderer): void {
	views.set(name, renderer);
}

export function modelAndView(name: string, model: Record<string, unknown> = {}, status = 200): Response {
	const renderer = views.get(name);
	if (!renderer) {
		throw new Error(`Unknown view '${name}' - register it with registerView() (see src/framework/views/)`);
	}
	return htmlResponse(renderer(model), status, {
		"cache-control": "no-cache, no-store, must-revalidate",
		pragma: "no-cache",
	});
}

export function jsonResponse(body: JsonValue | Record<string, unknown>, status = 200, headers?: HeadersInit): Response {
	const h = new Headers(headers);
	if (!h.has("content-type")) {
		h.set("content-type", "application/json");
	}
	return new Response(JSON.stringify(body), { status, headers: h });
}

export function textResponse(body: string, status = 200, headers?: HeadersInit): Response {
	const h = new Headers(headers);
	if (!h.has("content-type")) {
		h.set("content-type", "text/plain;charset=UTF-8");
	}
	return new Response(body, { status, headers: h });
}

export function htmlResponse(html: string, status = 200, headers?: HeadersInit): Response {
	const h = new Headers(headers);
	if (!h.has("content-type")) {
		h.set("content-type", "text/html;charset=UTF-8");
	}
	return new Response(html, { status, headers: h });
}

export function noContent(headers?: HeadersInit): Response {
	return new Response(null, { status: 204, headers });
}

/** Spring RedirectView: a 302 (default) redirect; the model is not appended to the URL */
export function redirectView(url: string, status = 302): Response {
	return new Response(null, { status, headers: { location: url } });
}

/** Generic ResponseEntity equivalent: body may be JSON, text or empty */
export function responseEntity(
	body: JsonValue | string | null | undefined,
	status: number,
	headers?: HeadersInit,
): Response {
	if (body == null || body === "") {
		return new Response(null, { status, headers });
	}
	if (typeof body === "string") {
		return textResponse(body, status, headers);
	}
	return jsonResponse(body, status, headers);
}

export function escapeHtml(s: unknown): string {
	return String(s)
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

/** Embed a value into an inline script as a JS literal (Thymeleaf [[${x}]] inline javascript) */
export function jsLiteral(v: unknown): string {
	return JSON.stringify(v ?? null).replaceAll("</", "<\\/");
}

const footer = `<footer><div>OpenID Foundation conformance suite (TypeScript port)</div></footer>`;

// Port of templates/implicitCallback.html
registerView("implicitCallback", (model) => {
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
});

// Port of templates/formPostResponseMode.html
registerView("formPostResponseMode", (model) => {
	const formAction = String(model["formAction"]);
	const formParameters = (model["formParameters"] ?? {}) as JsonObject;
	const inputs = Object.keys(formParameters)
		.map((p) => {
			const v = formParameters[p];
			const value = typeof v === "string" ? v : JSON.stringify(v);
			return `<div><input type="hidden" name="${escapeHtml(p)}" value="${escapeHtml(value)}"></div>`;
		})
		.join("\n            ");
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDF Conformance: form_post submission page</title>
    <meta http-equiv="Cache-control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
</head>
<body onload="submitform()">
    <div>
        <form action="${escapeHtml(formAction)}" method="post" enctype="application/x-www-form-urlencoded">
            ${inputs}
            <input type="submit" value="Click to submit the form manually">
        </form>
    </div>
    ${footer}
<script>
    function submitform(){
        document.forms[0].submit();
    }
</script>
</body>
</html>`;
});

// Port of templates/resultCaptured.html
registerView("resultCaptured", (model) => {
	const returnUrl = model["returnUrl"];
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDF Conformance: Result Captured</title>
</head>
<body>
    <div>
        <h1>Result captured</h1>
        <p>The test suite has received the result. You may return to <a href="${escapeHtml(returnUrl ?? "")}">the test results page.</a></p>
    </div>
    ${footer}
</body>
</html>`;
});
