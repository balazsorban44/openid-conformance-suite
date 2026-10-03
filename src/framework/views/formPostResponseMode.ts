import type { JsonObject } from "../json.ts";
import { escapeHtml, footer } from "./html.ts";

// Port of templates/formPostResponseMode.html
export function formPostResponseMode(model: Record<string, unknown>): string {
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
}
