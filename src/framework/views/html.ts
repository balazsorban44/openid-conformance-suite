/** Helpers shared by the view templates (ports of the Thymeleaf templates under src/main/resources/templates) */

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

export const footer = `<footer><div>OpenID Foundation conformance suite (TypeScript port)</div></footer>`;
