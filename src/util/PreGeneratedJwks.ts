import { generateKeyPairSync, type KeyObject } from "node:crypto";
import type { Environment } from "../framework/Environment.ts";
import type { JsonObject } from "../framework/json.ts";
import { JWKUtil, type JWK } from "./JWKUtil.ts";

/**
 * Owner-scoped, namespace-keyed cache of pre-generated JWK keypairs.
 *
 * <p>Conditions that previously generated a fresh keypair per call (RSA/EC/OKP
 * for client JWKs, server JWKs, DPoP, encryption keys, etc.) instead call
 * {@link PreGeneratedJwks.nextRsaKey} / {@link PreGeneratedJwks.nextEcKey} / {@link PreGeneratedJwks.nextOkpKey}
 * here, which returns a cached key for the current authenticated user. The cache key is
 * `(owner, slot, index)` where `owner` is the suite user's
 * `(sub, iss)` pair, `slot` is a constant string per
 * (kty, curve, key size), and `index` is a monotonic per-test-instance
 * counter on {@link Environment}, scoped per slot (each slot's indices start
 * at 0 independently).
 *
 * <p><b>Distinctness contract.</b> Within a single test instance, successive
 * calls for the same slot return entries at different indices, so two
 * back-to-back calls always return different keys. This satisfies the
 * framework's hard correctness gate `ValidateClientPrivateKeysAreDifferent`
 * (compares `client` vs `client2` thumbprints within one test).
 *
 * <p><b>Cap and overflow.</b> Hard cap of {@link PreGeneratedJwks.MAX_INDEX_PER_NAMESPACE}
 * distinct keys per `(owner, slot)` within a single test instance. A
 * request with index ≥ cap throws. No silent
 * modulo wrap — silent recycling would hide kid collisions in callers like
 * `VCIPrepareBatchProofKeys` and `keyIDFromThumbprint(true)`
 * paths.
 *
 * <p><b>Owner required.</b> If `env` is missing
 * `owner_sub` / `owner_iss` (set by
 * `AbstractTestModule.exposeOwnerIdToEnvironment()`), the public API
 * throws. Anonymous mode is an explicit test-only API
 * ({@link PreGeneratedJwks.borrowForTesting}) that callers must opt into.
 *
 * <p><b>TTL.</b> Entries are evicted when not touched within
 * {@link PreGeneratedJwks.retention}. An opportunistic sweep runs once per
 * `sweepInterval` on any read — no dedicated thread.
 *
 * <p><b>Concurrency.</b> Node runs conditions on a single thread and key generation here is synchronous, so the
 * Java single-flight machinery (per-key CompletableFuture, generation timeout) is not needed: a miss generates
 * the key and stores it before anything else can run.
 *
 * <p><b>Same-user parallel-test sharing.</b> Two parallel tests for the same
 * authenticated user both start at slot index 0 and therefore see the same
 * cached key. This is correctness-safe (no test inspects raw private bytes
 * across tests; thumbprint comparisons happen within a test) and is the
 * design we want — it minimises keygen across the process.
 *
 * Differences from Java: keys are returned as JSON JWKs including the private members (replacing Nimbus
 * `RSAKey`/`ECKey`/`OctetKeyPair`), and every call returns a fresh copy, so callers may add `kid`/`use`/`alg`
 * to the returned object (Java: `new RSAKey.Builder(key).keyID(...)`) without affecting the cache.
 * Curves are passed by their JWK name (`"P-256"`, `"secp256k1"`, `"Ed25519"`, ...), replacing Nimbus `Curve`.
 */
export class PreGeneratedJwks {
	/** Per-`(owner, slot)` distinct-key cap. Exceeding it throws. */
	static readonly MAX_INDEX_PER_NAMESPACE = 32;

	private static readonly DEFAULT_RETENTION_MS = 3 * 60 * 60 * 1000;
	private static readonly DEFAULT_SWEEP_INTERVAL_MS = 15 * 60 * 1000;

	private static retentionMs = PreGeneratedJwks.DEFAULT_RETENTION_MS;
	private static sweepIntervalMs = PreGeneratedJwks.DEFAULT_SWEEP_INTERVAL_MS;
	private static ticker: () => number = () => performance.now();

	/** namespace key (owner + slot) -> index -> entry */
	private static readonly CACHE = new Map<string, Map<number, { key: JWK; lastUsedAt: number }>>();
	private static lastSweep = 0;

	/** Sentinel owner used by the `*ForTesting` API. Never resolvable from a real {@link Environment}. */
	private static readonly ANONYMOUS_TEST_OWNER = { sub: "_test", iss: "_test" };

	private constructor() {}

	// ===== Public API =====

	/** Replaces `RSAKey nextRsaKey(Environment, int)`: returns a private RSA JWK (JSON). */
	static nextRsaKey(env: Environment, keySize: number): JWK {
		const owner = PreGeneratedJwks.resolveOwnerOrThrow(env);
		const slot = PreGeneratedJwks.rsaSlot(keySize);
		const idx = PreGeneratedJwks.nextIndex(env, slot);
		return PreGeneratedJwks.borrow(PreGeneratedJwks.namespaceKey(owner, slot), idx, () =>
			PreGeneratedJwks.generateRsa(keySize),
		);
	}

	/** Replaces `ECKey nextEcKey(Environment, Curve)`: `curve` is the JWK curve name; returns a private EC JWK. */
	static nextEcKey(env: Environment, curve: string): JWK {
		if (curve == null) {
			throw new TypeError("curve");
		}
		const owner = PreGeneratedJwks.resolveOwnerOrThrow(env);
		const slot = PreGeneratedJwks.ecSlot(curve);
		const idx = PreGeneratedJwks.nextIndex(env, slot);
		return PreGeneratedJwks.borrow(PreGeneratedJwks.namespaceKey(owner, slot), idx, () =>
			PreGeneratedJwks.generateEc(curve),
		);
	}

	/** Replaces `OctetKeyPair nextOkpKey(Environment, Curve)`: `curve` is the JWK curve name; returns a private OKP JWK. */
	static nextOkpKey(env: Environment, curve: string): JWK {
		if (curve == null) {
			throw new TypeError("curve");
		}
		const owner = PreGeneratedJwks.resolveOwnerOrThrow(env);
		const slot = PreGeneratedJwks.okpSlot(curve);
		const idx = PreGeneratedJwks.nextIndex(env, slot);
		return PreGeneratedJwks.borrow(PreGeneratedJwks.namespaceKey(owner, slot), idx, () =>
			PreGeneratedJwks.generateOkp(curve),
		);
	}

	// ===== Test-only API =====

	/** Test-only: drive the {@link PreGeneratedJwks.borrow} path with an explicit generator and `(slot, index)`,
	 *  bypassing owner resolution and the per-test counter. */
	static borrowForTesting(slot: string, index: number, generator: () => JWK): JWK {
		return PreGeneratedJwks.borrow(
			PreGeneratedJwks.namespaceKey(PreGeneratedJwks.ANONYMOUS_TEST_OWNER, slot),
			index,
			generator,
		);
	}

	static setRetentionForTesting(ms: number): void {
		PreGeneratedJwks.retentionMs = ms;
	}

	static setSweepIntervalForTesting(ms: number): void {
		PreGeneratedJwks.sweepIntervalMs = ms;
	}

	static setTickerForTesting(t: () => number): void {
		PreGeneratedJwks.ticker = t;
	}

	/** Test-only: reset everything to defaults. */
	static clear(): void {
		PreGeneratedJwks.CACHE.clear();
		PreGeneratedJwks.lastSweep = 0;
		PreGeneratedJwks.retentionMs = PreGeneratedJwks.DEFAULT_RETENTION_MS;
		PreGeneratedJwks.sweepIntervalMs = PreGeneratedJwks.DEFAULT_SWEEP_INTERVAL_MS;
		PreGeneratedJwks.ticker = () => performance.now();
	}

	/** Retention in milliseconds (Java returns a Duration). */
	static retention(): number {
		return PreGeneratedJwks.retentionMs;
	}

	// ===== Internals =====

	private static namespaceKey(owner: { sub: string; iss: string }, slot: string): string {
		return JSON.stringify([owner.sub, owner.iss, slot]);
	}

	private static resolveOwnerOrThrow(env: Environment): { sub: string; iss: string } {
		if (env == null) {
			throw new TypeError("env");
		}
		const sub = env.getString("owner_sub");
		const iss = env.getString("owner_iss");
		if (sub == null || iss == null) {
			throw new Error(
				"PreGeneratedJwks: owner_sub/owner_iss are missing from the environment. " +
					"AbstractTestModule.exposeOwnerIdToEnvironment() should have set them. " +
					"If this is a unit-test context, use the *ForTesting helpers instead.",
			);
		}
		return { sub, iss };
	}

	private static nextIndex(env: Environment, slot: string): number {
		const idx = env.nextSystemCounter("PreGeneratedJwks." + slot);
		if (idx >= PreGeneratedJwks.MAX_INDEX_PER_NAMESPACE) {
			throw new Error(
				"PreGeneratedJwks: per-test-instance cap of " +
					PreGeneratedJwks.MAX_INDEX_PER_NAMESPACE +
					" distinct " +
					slot +
					" keys exceeded (requested index " +
					idx +
					"). " +
					"Either raise PreGeneratedJwks.MAX_INDEX_PER_NAMESPACE or refactor the test " +
					"to need fewer distinct keys per instance.",
			);
		}
		return idx;
	}

	private static borrow(namespace: string, index: number, generator: () => JWK): JWK {
		PreGeneratedJwks.maybeSweep();

		// Fast path: hot cache hit, refresh lastUsed, return.
		const ns = PreGeneratedJwks.CACHE.get(namespace);
		const hit = ns?.get(index);
		if (hit != null && !PreGeneratedJwks.isExpired(hit.lastUsedAt)) {
			hit.lastUsedAt = PreGeneratedJwks.ticker();
			return structuredClone(hit.key);
		}

		// Cold path: generate and store.
		let fresh: JWK;
		try {
			fresh = generator();
		} catch (e) {
			if (e instanceof Error) {
				throw e;
			}
			throw new Error("PreGeneratedJwks generation failed", { cause: e });
		}
		let target = PreGeneratedJwks.CACHE.get(namespace);
		if (target == null) {
			target = new Map();
			PreGeneratedJwks.CACHE.set(namespace, target);
		}
		target.set(index, { key: fresh, lastUsedAt: PreGeneratedJwks.ticker() });
		return structuredClone(fresh);
	}

	private static isExpired(lastUsedAt: number): boolean {
		return PreGeneratedJwks.ticker() - lastUsedAt > PreGeneratedJwks.retentionMs;
	}

	private static maybeSweep(): void {
		const now = PreGeneratedJwks.ticker();
		const prev = PreGeneratedJwks.lastSweep;
		if (prev !== 0 && now - prev < PreGeneratedJwks.sweepIntervalMs) {
			return;
		}
		PreGeneratedJwks.lastSweep = now;
		for (const [nsKey, ns] of PreGeneratedJwks.CACHE) {
			for (const [index, entry] of ns) {
				if (PreGeneratedJwks.isExpired(entry.lastUsedAt)) {
					ns.delete(index);
				}
			}
			if (ns.size === 0) {
				PreGeneratedJwks.CACHE.delete(nsKey);
			}
		}
	}

	private static rsaSlot(keySize: number): string {
		return "rsa-" + keySize;
	}

	private static ecSlot(curve: string): string {
		return "ec-" + curve.toLowerCase();
	}

	private static okpSlot(curve: string): string {
		return "okp-" + curve.toLowerCase();
	}

	private static toJwk(privateKey: KeyObject): JWK {
		// normalize to Nimbus' member order
		return JWKUtil.parseJWK(privateKey.export({ format: "jwk" }) as JsonObject);
	}

	private static generateRsa(keySize: number): JWK {
		try {
			const { privateKey } = generateKeyPairSync("rsa", { modulusLength: keySize, publicExponent: 0x10001 });
			return PreGeneratedJwks.toJwk(privateKey);
		} catch (e) {
			throw new Error("Failed to generate RSA-" + keySize, { cause: e });
		}
	}

	private static readonly EC_NAMED_CURVES: Record<string, string> = {
		"P-256": "prime256v1",
		"P-384": "secp384r1",
		"P-521": "secp521r1",
		secp256k1: "secp256k1",
	};

	private static generateEc(curve: string): JWK {
		try {
			const namedCurve = PreGeneratedJwks.EC_NAMED_CURVES[curve];
			if (namedCurve == null) {
				throw new Error("Unsupported curve: " + curve);
			}
			const { privateKey } = generateKeyPairSync("ec", { namedCurve });
			return PreGeneratedJwks.toJwk(privateKey);
		} catch (e) {
			throw new Error("Failed to generate EC " + curve, { cause: e });
		}
	}

	private static generateOkp(curve: string): JWK {
		try {
			let privateKey: KeyObject;
			switch (curve) {
				case "Ed25519":
					privateKey = generateKeyPairSync("ed25519").privateKey;
					break;
				case "Ed448":
					privateKey = generateKeyPairSync("ed448").privateKey;
					break;
				case "X25519":
					privateKey = generateKeyPairSync("x25519").privateKey;
					break;
				case "X448":
					privateKey = generateKeyPairSync("x448").privateKey;
					break;
				default:
					throw new Error("Unsupported curve: " + curve);
			}
			return PreGeneratedJwks.toJwk(privateKey);
		} catch (e) {
			throw new Error("Failed to generate OKP " + curve, { cause: e });
		}
	}
}
