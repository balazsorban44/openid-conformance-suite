/**
 * Process-wide in-memory cache for outgoing HTTP responses (used by the
 * {@link CachingHttpInterceptor} to avoid re-fetching stable OP metadata
 * like {@code /.well-known/openid-configuration}, JWKS sets, and VCI
 * issuer metadata).
 *
 * <p>The eligibility decision (which requests to cache) lives in
 * {@link CachingHttpInterceptor}; this class is a dumb store keyed by an
 * opaque string the interceptor builds.
 *
 * <p><b>Single-flight on miss:</b> concurrent {@link #getOrFetch} calls
 * for the same key share one fetch via a per-key in-flight
 * {@link Promise}, so CI runs with many parallel test plans
 * against the same upstream OP issue at most one HTTP call per URL.
 *
 * <p><b>Successful responses only.</b> If the supplied fetcher throws,
 * nothing is cached and the next call invokes the fetcher again (no
 * negative caching). The exception propagates to ALL waiting callers.
 *
 * <p>Entries expire after {@link #DEFAULT_TTL} (1 hour) unless overridden
 * via {@link #setTtlForTesting}. {@link #clear} resets the TTL override
 * back to the default so tests cannot leak overrides into one another.
 *
 * <p>Singleton because conformance-suite conditions are instantiated via
 * reflective {@code newInstance()} with no Spring DI; a static facade is
 * the simplest way to share state across instances.
 *
 * Port notes: Java {@code Duration} values are milliseconds (number), {@code Instant} is a {@link Date},
 * {@code HttpHeaders} is the web {@link Headers}, {@code byte[]} is {@link Uint8Array},
 * {@code Optional<Entry>} is {@code Entry | null} and {@code CompletableFuture} is {@link Promise}.
 */

/** A fetcher that produces an {@link Entry} or throws on any failure
 *  (network error, etc.). */
export type Fetcher = () => Promise<Entry> | Entry;

/** One cached HTTP response. {@code body} is the raw response bytes
 *  (treat as immutable - never mutate the array after construction);
 *  {@code headers} is a defensive copy. */
export class Entry {
	readonly body: Uint8Array;
	readonly statusCode: number;
	readonly statusText: string;
	readonly headers: Headers;
	readonly cachedAt: Date;

	constructor(body: Uint8Array, statusCode: number, statusText: string, headers: Headers, cachedAt: Date) {
		this.body = body;
		this.statusCode = statusCode;
		this.statusText = statusText;
		this.headers = headers;
		this.cachedAt = cachedAt;
	}

	/** Wall-clock seconds since this entry was cached. */
	ageSeconds(): number {
		return Math.trunc((Date.now() - this.cachedAt.getTime()) / 1000);
	}
}

export class ExternalEndpointCache {
	private static readonly DEFAULT_TTL = 60 * 60 * 1000; // Duration.ofHours(1), in milliseconds
	private static readonly ENTRIES = new Map<string, Entry>();
	private static readonly IN_FLIGHT = new Map<string, Promise<Entry>>();
	private static ttl: number = ExternalEndpointCache.DEFAULT_TTL;

	private constructor() {}

	/** Returns the cached entry for {@code key} if present and not yet
	 *  expired; otherwise null. */
	static get(key: string): Entry | null {
		const e = ExternalEndpointCache.ENTRIES.get(key);
		if (e === undefined) {
			return null;
		}
		if (Date.now() - e.cachedAt.getTime() > ExternalEndpointCache.ttl) {
			if (ExternalEndpointCache.ENTRIES.get(key) === e) {
				ExternalEndpointCache.ENTRIES.delete(key);
			}
			return null;
		}
		return e;
	}

	/** Return the cached entry for {@code key} if fresh; otherwise invoke
	 *  {@code fetcher} and cache the result. Concurrent misses for the
	 *  same key share one fetch. When {@code shouldCache} is given, the
	 *  fetched entry is only committed to the cache when it returns true.
	 *  Single-flight protection still applies - concurrent
	 *  callers share one fetch regardless of the predicate's verdict -
	 *  but a "don't cache" verdict means the next call after the elected
	 *  fetcher completes will re-fetch. Typical use: don't cache non-2xx
	 *  HTTP responses. */
	static async getOrFetch(
		key: string,
		fetcher: Fetcher,
		shouldCache: (entry: Entry) => boolean = () => true,
	): Promise<Entry> {
		const hit = ExternalEndpointCache.get(key);
		if (hit !== null) {
			return hit;
		}

		// (the check for an in-flight fetch and the registration of our own happen without an await in between,
		// which is the equivalent of ConcurrentHashMap.putIfAbsent)
		const existing = ExternalEndpointCache.IN_FLIGHT.get(key);
		if (existing !== undefined) {
			return await existing;
		}
		let resolveMine!: (entry: Entry) => void;
		let rejectMine!: (reason: unknown) => void;
		const mine = new Promise<Entry>((resolve, reject) => {
			resolveMine = resolve;
			rejectMine = reject;
		});
		// nobody may be waiting on it; avoid an unhandled rejection
		mine.catch(() => {});
		ExternalEndpointCache.IN_FLIGHT.set(key, mine);

		// We're the elected fetcher.
		try {
			const fresh = await fetcher();
			if (fresh == null) {
				throw new Error("fetcher returned null Entry for " + key);
			}
			if (shouldCache(fresh)) {
				ExternalEndpointCache.ENTRIES.set(key, fresh);
			}
			resolveMine(fresh);
			return fresh;
		} catch (t) {
			rejectMine(t);
			throw t;
		} finally {
			if (ExternalEndpointCache.IN_FLIGHT.get(key) === mine) {
				ExternalEndpointCache.IN_FLIGHT.delete(key);
			}
		}
	}

	/** Drop every cached entry AND reset the testing TTL override.
	 *  Intended for test isolation - call from {@code @BeforeEach}. */
	static clear(): void {
		ExternalEndpointCache.ENTRIES.clear();
		ExternalEndpointCache.IN_FLIGHT.clear();
		ExternalEndpointCache.ttl = ExternalEndpointCache.DEFAULT_TTL;
	}

	/** Override the TTL (in milliseconds) for the lifetime of the process (or until {@link #clear}
	 *  is called). Intended for unit tests so they don't have to wait an
	 *  hour. Production paths should not touch this. */
	static setTtlForTesting(newTtl: number): void {
		ExternalEndpointCache.ttl = newTtl;
	}
}
