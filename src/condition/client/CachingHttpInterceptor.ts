import { decodeBody, type Environment, type HttpResponse } from "../../framework/index.ts";
import { Entry, ExternalEndpointCache } from "./ExternalEndpointCache.ts";

/**
 * Port of logging/CachedHttpResponseMarker.java: implemented by synthesized responses that replay a
 * previously cached response, so the HTTP logging can label the resulting log entry as a cache hit
 * rather than emitting a separate one.
 *
 * Port note: the marker is HttpResponse's optional `cacheAgeSeconds` field, which HttpClient checks.
 */
export interface CachedHttpResponseMarker {
	readonly cacheAgeSeconds: number;
}

/** The parts of Spring's HttpRequest that the interceptor looks at (method, URI and headers) */
export interface InterceptedHttpRequest {
	method: string;
	url: string;
	headers: Headers;
}

/**
 * Runs the real HTTP call (Spring: ClientHttpRequestExecution.execute(req, body)); the request body is captured
 * by the closure.
 */
export type ClientHttpRequestExecution = () => Promise<HttpResponse>;

/**
 * Spring {@link ClientHttpRequestInterceptor} that consults
 * {@link ExternalEndpointCache} before issuing the real HTTP call.
 * Opt-in: install via {@code AbstractCondition.createRestTemplateWithCache}.
 *
 * <p>Cache key = {@code METHOD " " URI " | Accept=" h " | Accept-Language=" h}
 * — request headers that change the response (Accept for signed-vs-unsigned
 * metadata, Accept-Language for content-negotiation) are part of the key, so
 * two tests issuing different headers don't collide.
 *
 * <p>Eligibility gate (see {@link #shouldCache}): a test config opts in by
 * setting {@code "options": {"cache_external_metadata": true}}. Default off.
 * Only {@code GET} requests are cached (metadata/JWKS fetches); any other
 * method is passed straight through, since the cache key does not incorporate
 * a request body.
 *
 * <p><b>Do not enable this for tests that deliberately observe a metadata or
 * JWKS change at the same URL</b> (e.g. {@code oidcc-server-rotate-keys},
 * which re-fetches {@code jwks_uri} after a key rotation and expects to see
 * the new key). Within the {@link ExternalEndpointCache} TTL the second fetch
 * would be served the stale pre-rotation response. The opt-in CI configs that
 * set the flag today do not exercise any such rotation flow.
 *
 * <p>On a cache hit a synthetic {@link ClientHttpResponse} is returned
 * (tagged with {@link CachedHttpResponseMarker}) without invoking the
 * downstream execution, so the real HTTP call is skipped. The outer
 * {@link net.openid.conformance.logging.LoggingRequestInterceptor} detects
 * the marker and relabels its single "HTTP response" log entry as
 * "Using cached HTTP response", so the test event log makes the cache hit
 * visible without a duplicate entry.
 *
 * Port notes: the TypeScript HttpClient has no interceptor chain, so `intercept` takes the request and a
 * closure that performs the real call, and returns an HttpResponse (a {@link CachedClientHttpResponse},
 * which carries the {@link CachedHttpResponseMarker}, on a cache hit).
 */
export class CachingHttpInterceptor {
	private readonly env: Environment;

	constructor(env: Environment) {
		this.env = env;
	}

	async intercept(req: InterceptedHttpRequest, exec: ClientHttpRequestExecution): Promise<HttpResponse> {
		// Only GET is cached: the cache key omits the request body, so caching
		// any body-bearing method could serve one request's response to another.
		if (!this.shouldCache() || req.method !== "GET") {
			return await exec();
		}

		const key = CachingHttpInterceptor.buildKey(req);
		const probe = ExternalEndpointCache.get(key);
		if (probe !== null) {
			// LoggingRequestInterceptor (registered outside us) will detect the
			// CachedHttpResponseMarker and relabel its single "HTTP response"
			// log entry as "Using cached HTTP response" — no separate entry
			// from here.
			return new CachedClientHttpResponse(probe, req.url);
		}

		// Cache 2xx only - transient 4xx/5xx must not be pinned for the
		// TTL window. Single-flight still applies on a miss so concurrent
		// failed fetches share the same response without each issuing
		// its own HTTP call.
		const fresh = await ExternalEndpointCache.getOrFetch(
			key,
			async () => CachingHttpInterceptor.capture(await exec()),
			(e) => e.statusCode >= 200 && e.statusCode < 300,
		);
		// Miss path: a network fetch actually happened (either by us or
		// the single-flight winner). Return the un-marked variant so
		// LoggingRequestInterceptor logs it as the normal "HTTP response",
		// not a cache hit — cache "hits" must reflect reuse of a
		// previously-populated entry, not the populating fetch itself.
		return new ReplayedClientHttpResponse(fresh, req.url);
	}

	/** A test config opts into caching by setting
	 *  {@code "options": {"cache_external_metadata": true}}. */
	private shouldCache(): boolean {
		return this.env.getBoolean("config", "options.cache_external_metadata") === true;
	}

	/** Build a cache key that incorporates the request method, URI, and the
	 *  headers that can change the response (Accept governs JSON vs JWT for
	 *  signed metadata; Accept-Language affects localized metadata). */
	private static buildKey(req: InterceptedHttpRequest): string {
		const headers = req.headers;
		return (
			req.method +
			" " +
			req.url +
			" | Accept=" +
			headers.get("Accept") +
			" | Accept-Language=" +
			headers.get("Accept-Language")
		);
	}

	/** Drain the response body into a byte array and snapshot the status +
	 *  headers, so the original (streaming) response can be discarded and
	 *  replayed from the cache. */
	private static capture(resp: HttpResponse): Entry {
		// the HttpClient has already buffered the body (resp.bodyBytes)
		const bodyBytes = resp.bodyBytes;
		const snapshot = new Headers(resp.headers);
		return new Entry(bodyBytes, resp.status, resp.statusText, snapshot, new Date());
	}
}

/** Synthesizes a {@link ClientHttpResponse} from a cache entry, used on
 *  the miss path so the captured body can be returned upstream after the
 *  fetcher has drained and closed the real streaming response. Does NOT
 *  carry the {@link CachedHttpResponseMarker}, so
 *  {@link net.openid.conformance.logging.LoggingRequestInterceptor} logs
 *  it as a normal "HTTP response". */
class ReplayedClientHttpResponse implements HttpResponse {
	protected readonly entry: Entry;
	readonly url: string;

	constructor(entry: Entry, url: string) {
		this.entry = entry;
		this.url = url;
	}

	get status(): number {
		return this.entry.statusCode;
	}

	get statusText(): string {
		return this.entry.statusText;
	}

	get headers(): Headers {
		return this.entry.headers;
	}

	get bodyBytes(): Uint8Array {
		return this.entry.body;
	}

	get body(): string | null {
		return decodeBody(this.entry.body);
	}
}

/** True cache-hit variant of {@link ReplayedClientHttpResponse}, returned
 *  only when the entry was already present at lookup time. The
 *  {@link CachedHttpResponseMarker} tells
 *  {@link net.openid.conformance.logging.LoggingRequestInterceptor} to
 *  relabel its log entry as "Using cached HTTP response". */
export class CachedClientHttpResponse extends ReplayedClientHttpResponse implements CachedHttpResponseMarker {
	readonly cacheAgeSeconds: number;

	constructor(entry: Entry, url: string) {
		super(entry, url);
		this.cacheAgeSeconds = entry.ageSeconds();
	}
}
