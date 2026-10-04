/**
 * Requests that start or stop processes must come from the UI itself: a JSON body (a cross-site form or a
 * `text/plain` fetch cannot send one without a CORS preflight, which this server never answers) and, when the
 * browser says where the request comes from, the same host.
 */
export function rejectCrossSite(request: Request, { json }: { json: boolean }): Response | null {
	if (json && !request.headers.get("content-type")?.startsWith("application/json")) {
		return Response.json({ error: "expected an application/json body" }, { status: 415 });
	}
	const origin = request.headers.get("origin");
	const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
	if (origin && host && new URL(origin).host !== host) {
		return Response.json({ error: "cross-site request" }, { status: 403 });
	}
	return null;
}
