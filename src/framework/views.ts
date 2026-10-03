import type { JsonValue } from "./json.ts";
import { checkSessionIFrame } from "./views/checkSessionIFrame.ts";
import { formPostResponseMode } from "./views/formPostResponseMode.ts";
import { implicitCallback } from "./views/implicitCallback.ts";
import { oidccFrontChannelLogout } from "./views/oidccFrontChannelLogout.ts";
import { resultCaptured } from "./views/resultCaptured.ts";
import { rpSessionIframe } from "./views/rpSessionIframe.ts";
import { sessionVerify } from "./views/sessionVerify.ts";

export { escapeHtml, jsLiteral } from "./views/html.ts";

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

/** The view templates (ports of the Thymeleaf templates under src/main/resources/templates), one file each */
const views = {
	checkSessionIFrame,
	formPostResponseMode,
	implicitCallback,
	oidccFrontChannelLogout,
	resultCaptured,
	rpSessionIframe,
	sessionVerify,
} satisfies Record<string, ViewRenderer>;

export type ViewName = keyof typeof views;

export function modelAndView(name: ViewName, model: Record<string, unknown> = {}, status = 200): Response {
	return htmlResponse(views[name](model), status, {
		"cache-control": "no-cache, no-store, must-revalidate",
		pragma: "no-cache",
	});
}

function withDefaultContentType(
	body: string,
	contentType: string,
	status: number,
	headers: HeadersInit | undefined,
): Response {
	const h = new Headers(headers);
	if (!h.has("content-type")) {
		h.set("content-type", contentType);
	}
	return new Response(body, { status, headers: h });
}

export function jsonResponse(body: JsonValue | Record<string, unknown>, status = 200, headers?: HeadersInit): Response {
	return withDefaultContentType(JSON.stringify(body), "application/json", status, headers);
}

export function textResponse(body: string, status = 200, headers?: HeadersInit): Response {
	return withDefaultContentType(body, "text/plain;charset=UTF-8", status, headers);
}

export function htmlResponse(html: string, status = 200, headers?: HeadersInit): Response {
	return withDefaultContentType(html, "text/html;charset=UTF-8", status, headers);
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
