import { escapeHtml, footer } from "./html.ts";

// Port of templates/resultCaptured.html
export function resultCaptured(model: Record<string, unknown>): string {
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
}
