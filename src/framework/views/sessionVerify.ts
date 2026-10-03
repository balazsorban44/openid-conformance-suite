import { escapeHtml, registerView } from "../views.ts";

// Port of templates/sessionVerify.html
// th:src="${x}" -> an escaped src attribute (Thymeleaf omits the attribute when the value is null)
registerView("sessionVerify", (model) => {
	const src = (v: unknown) => (v == null ? "" : ` src="${escapeHtml(v)}"`);
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <title>OIDF Conformance Suite: Session verification</title>
</head>
<body>

<h1>Session verification</h1>
<h2>Checking that the session hasn't changed!</h2>
<p>If you see this frame for more than a few seconds something has gone wrong.</p>
<iframe id="op_iframe"${src(model["check_session_iframe"])} hidden></iframe>
<iframe id="rp_iframe"${src(model["session_iframe_unchanged"])} hidden></iframe>

</body>
</html>`;
});
