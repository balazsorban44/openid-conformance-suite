/**
 * The emulated OP's own keys: generated per test (upstream OIDCCGenerateServerJWKs and its variants), published at
 * `jwks_uri` (with five deliberately unusable keys), validated before the test starts.
 */
import { generateKeyPairSync, randomInt, randomUUID, type KeyObject } from "node:crypto";
import { checkDistinctKeyIdValueInServerJWKs, validateJwks } from "../op/jwks.ts";
import { condition, soft, type Condition } from "../suite/conditions.ts";
import type { TestConfig } from "../suite/config.ts";
import { ParseException } from "../suite/errors.ts";
import { generateJwkForAlg, privateJwks, publicJwks, type JWK, type Jwks } from "../suite/jose.ts";
import { getPublicJwksAsJsonObject, parseJWK, parseJWKSet, toPublicJWK } from "../suite/jose-jwk.ts";

/** upstream env "server_jwks" (the signing keys in use), "server_public_jwks" (published), "server_encryption_keys" */
export interface ServerKeys {
	jwks: Jwks;
	publicJwks: Jwks;
	encryptionKeys: Jwks;
}

/** How many keys of each kind OIDCCGenerateServerJWKs creates (its setters) */
export interface ServerJwksParameters {
	numberOfRSASigningKeysWithNoAlg: number;
	numberOfECCurveP256SigningKeysWithNoAlg: number;
	numberOfECCurveSECP256KSigningKeysWithNoAlg: number;
	numberOfOKPSigningKeysWithNoAlg: number;
	numberOfRSSigningKeys: number;
	numberOfPSSigningKeys: number;
	numberOfES256SigningKeys: number;
	numberOfEdSigningKeys: number;
	numberOfRSAEncKeys: number;
	numberOfECEncKeys: number;
	generateSigKids: boolean;
	generateEncKids: boolean;
}

const DEFAULT_PARAMETERS: ServerJwksParameters = {
	numberOfRSASigningKeysWithNoAlg: 2,
	numberOfECCurveP256SigningKeysWithNoAlg: 2,
	numberOfECCurveSECP256KSigningKeysWithNoAlg: 1,
	numberOfOKPSigningKeysWithNoAlg: 1,
	numberOfRSSigningKeys: 0,
	numberOfPSSigningKeys: 0,
	numberOfES256SigningKeys: 0,
	numberOfEdSigningKeys: 0,
	numberOfRSAEncKeys: 1,
	numberOfECEncKeys: 1,
	generateSigKids: true,
	generateEncKids: true,
};

/**
 * Key pairs are expensive to generate (RSA), so like upstream's PreGeneratedJwks they come from a process-wide pool:
 * the n-th key of a kind in a test is the n-th key of the pool (a fresh kid is still set per test).
 */
const pool = new Map<string, JWK[]>();

function pooledKey(slot: "rsa-2048" | "ec-p-256" | "ec-secp256k1" | "okp-ed25519", index: number): JWK {
	const keys = pool.get(slot) ?? [];
	pool.set(slot, keys);
	while (keys.length <= index) {
		let privateKey: KeyObject;
		if (slot === "rsa-2048") {
			privateKey = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 0x10001 }).privateKey;
		} else if (slot === "ec-p-256") {
			privateKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey;
		} else if (slot === "ec-secp256k1") {
			privateKey = generateKeyPairSync("ec", { namedCurve: "secp256k1" }).privateKey;
		} else {
			privateKey = generateKeyPairSync("ed25519").privateKey;
		}
		// normalized to Nimbus' member order
		keys.push(parseJWK(privateKey.export({ format: "jwk" }) as Record<string, unknown> as never));
	}
	return structuredClone(keys[index]);
}

/**
 * The body of OIDCCGenerateServerJWKs (createKeys). `name` is the condition (the variants of OIDCCGenerateServerJWKs
 * only change the parameters).
 */
function generateServerJwks(
	name: string,
	parameters: Partial<ServerJwksParameters>,
	requirements: string[],
): ServerKeys {
	const p: ServerJwksParameters = { ...DEFAULT_PARAMETERS, ...parameters };
	const c: Condition = condition(name, ...requirements);
	const all: JWK[] = [];
	const signing: JWK[] = [];
	const encryption: JWK[] = [];
	const used = new Map<string, number>();
	const create = (
		count: number,
		slot: "rsa-2048" | "ec-p-256" | "ec-secp256k1" | "okp-ed25519",
		use: "sig" | "enc",
		alg: string | null,
	) => {
		if (count < 1) {
			return;
		}
		// a random key of several is the signing key (upstream getIndexOfKeyToUse)
		const whichKeyToUse = count < 2 ? 0 : randomInt(0, count);
		for (let i = 0; i < count; i++) {
			const kid = (p.generateSigKids && use === "sig") || (p.generateEncKids && use === "enc") ? randomUUID() : null;
			const index = used.get(slot) ?? 0;
			used.set(slot, index + 1);
			const key = pooledKey(slot, index);
			key["use"] = use;
			if (kid != null) {
				key["kid"] = kid;
			}
			if (alg != null) {
				key["alg"] = alg;
			}
			all.push(key);
			if (use === "enc") {
				encryption.push(key);
			}
			if (i === whichKeyToUse && use === "sig") {
				signing.push(key);
			}
		}
	};
	// changing the order here may affect the signing key selection (selectAsymmetricJWSKey)
	create(p.numberOfRSASigningKeysWithNoAlg, "rsa-2048", "sig", null);
	create(p.numberOfECCurveP256SigningKeysWithNoAlg, "ec-p-256", "sig", null);
	create(p.numberOfECCurveSECP256KSigningKeysWithNoAlg, "ec-secp256k1", "sig", null);
	create(p.numberOfOKPSigningKeysWithNoAlg, "okp-ed25519", "sig", null);
	create(p.numberOfRSSigningKeys, "rsa-2048", "sig", "RS256");
	create(p.numberOfES256SigningKeys, "ec-p-256", "sig", "ES256");
	create(p.numberOfPSSigningKeys, "rsa-2048", "sig", "PS256");
	create(p.numberOfEdSigningKeys, "okp-ed25519", "sig", "EdDSA");
	create(p.numberOfRSAEncKeys, "rsa-2048", "enc", "RSA-OAEP");
	create(p.numberOfECEncKeys, "ec-p-256", "enc", "ECDH-ES");

	const keys: ServerKeys = {
		publicJwks: publicJwks({ keys: all }),
		jwks: privateJwks({ keys: signing }),
		encryptionKeys: privateJwks({ keys: encryption }),
	};
	c.log("Generated server public private JWK sets", {
		server_public_jwks: keys.publicJwks,
		server_jwks: keys.jwks,
		server_encryption_keys: keys.encryptionKeys,
	});
	return keys;
}

/** upstream: condition/as/OIDCCGenerateServerJWKs.java */
export function oidccGenerateServerJWKs(...requirements: string[]): ServerKeys {
	return generateServerJwks("OIDCCGenerateServerJWKs", {}, requirements);
}

/** upstream: condition/as/OIDCCGenerateServerJWKsSingleSigningKeyWithNoKeyId.java */
export function oidccGenerateServerJWKsSingleSigningKeyWithNoKeyId(...requirements: string[]): ServerKeys {
	return generateServerJwks(
		"OIDCCGenerateServerJWKsSingleSigningKeyWithNoKeyId",
		{
			generateSigKids: false,
			numberOfRSASigningKeysWithNoAlg: 1,
			numberOfECCurveP256SigningKeysWithNoAlg: 1,
			numberOfECCurveSECP256KSigningKeysWithNoAlg: 1,
			numberOfOKPSigningKeysWithNoAlg: 1,
		},
		requirements,
	);
}

/** upstream: condition/as/OIDCCGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds.java */
export function oidccGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds(...requirements: string[]): ServerKeys {
	return generateServerJwks(
		"OIDCCGenerateServerJWKsMultipleSigningsKeyWithNoKeyIds",
		{
			generateSigKids: false,
			numberOfRSASigningKeysWithNoAlg: 3,
			numberOfECCurveP256SigningKeysWithNoAlg: 3,
			numberOfECCurveSECP256KSigningKeysWithNoAlg: 3,
			numberOfOKPSigningKeysWithNoAlg: 3,
		},
		requirements,
	);
}

/** Keys published at jwks_uri that a conformant RP must ignore (upstream AddUnusableKeysToServerPublicJwks) */
const UNUSABLE_KEYS: Record<string, unknown>[] = [
	// A post-quantum (ML-DSA) shaped key with a non-existent parameter set, so it is realistic but can never become
	// usable. 'pub' is an arbitrary placeholder - the key type is unsupported.
	{
		kty: "AKP",
		alg: "ML-DSA-9999",
		kid: "unusable-pq-sig-key",
		use: "sig",
		pub: "Z0FOY29uZm9ybWFuY2UtdGVzdC1wbGFjZWhvbGRlci1wdWJsaWMta2V5",
	},
	// A made-up key type that no JOSE implementation supports.
	{
		kty: "OIDF-CONFORMANCE-UNSUPPORTED",
		alg: "OIDF-CONFORMANCE-UNSUPPORTED",
		kid: "unusable-unknown-kty-key",
		use: "sig",
	},
	// A parseable RSA key (RFC 7517 Appendix A.1) whose alg does not exist.
	{
		kty: "RSA",
		alg: "RS9999",
		kid: "unusable-rsa-unknown-alg-key",
		use: "sig",
		n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		e: "AQAB",
	},
	// A parseable EC key (RFC 7517 Appendix A.1) whose alg does not exist.
	{
		kty: "EC",
		crv: "P-256",
		alg: "ES9999",
		kid: "unusable-ec-unknown-alg-key",
		use: "sig",
		x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	},
	// An EC key with a non-existent crv (and no alg, so alg filtering still hits the unknown curve).
	{
		kty: "EC",
		crv: "P-9999",
		kid: "unusable-ec-unknown-crv-key",
		use: "sig",
		x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	},
];

/** upstream: condition/as/AddUnusableKeysToServerPublicJwks.java */
export function addUnusableKeysToServerPublicJwks(keys: ServerKeys, ...requirements: string[]): void {
	const c: Condition = condition("AddUnusableKeysToServerPublicJwks", ...requirements);
	if (!Array.isArray(keys.publicJwks.keys)) {
		c.failure(
			"server_public_jwks with a 'keys' array was not found. This condition must run after the server JWKS have been generated.",
		);
	}
	for (const key of UNUSABLE_KEYS) {
		(keys.publicJwks.keys as unknown[]).push(structuredClone(key));
	}
	c.log(
		"Added five unusable signing keys to the published server_public_jwks: a post-quantum-shaped " +
			"key with a non-existent parameter set, a made-up key type, an RSA key with an unknown alg, " +
			"an EC key with an unknown alg, and an EC key with an unknown crv. A conformant relying " +
			"party must ignore them and verify the id_token using the real key (RFC 7517 section 5).",
		{ server_public_jwks: keys.publicJwks },
	);
}

/**
 * The suite's own signing keys pass the generic JWK set validation (private keys allowed).
 *
 * upstream: AbstractOIDCCClientTest.validateConfiguredServerJWKS without CheckDistinctKeyIdValueInServerJWKs (the
 * modules that publish keys without kid override it like this)
 */
export async function validateServerSigningKeys(keys: ServerKeys): Promise<void> {
	await validateJwks(keys.jwks, "server signing keys", { requirements: ["RFC7517-1.1"], allowPrivateKeys: true });
}

/**
 * The default keys of the emulated OP: generated, published with five unusable keys (in every RP test rather than
 * a dedicated module, so the check does not depend on when the RP last fetched the JWKS), then validated.
 *
 * upstream: AbstractOIDCCClientTest.configureServerJWKS + validateConfiguredServerJWKS
 */
export async function configureServerJwks(): Promise<ServerKeys> {
	const keys = oidccGenerateServerJWKs();
	addUnusableKeysToServerPublicJwks(keys, "RFC7517-5");
	await validateServerSigningKeys(keys);
	soft(() => checkDistinctKeyIdValueInServerJWKs(keys.jwks, "RFC7517-4.5"));
	return keys;
}

/** The jwks_uri response (upstream handleJwksEndpointRequest: an empty "Jwks endpoint" block) */
export function jwksResponse(keys: ServerKeys): Response {
	return Response.json(keys.publicJwks);
}

/**
 * New keys (new kids) for a key rotation: generated and published with the unusable keys, not validated again.
 *
 * upstream: AbstractOIDCCClientTest.configureServerJWKS (as the key rotation modules call it again)
 */
export function regenerateServerJwks(): ServerKeys {
	const keys = oidccGenerateServerJWKs();
	addUnusableKeysToServerPublicJwks(keys, "RFC7517-5");
	return keys;
}

// ---------------------------------------------------------------------------------------------------------------
// the FAPI 2 authorization server's keys (upstream AbstractFAPI2SPFinalClientTest.configureServerJWKS)

/**
 * The keys of the configuration (`server.jwks`), split into the private set, the public set and the encryption
 * keys (the keys without `use` or with use=enc).
 *
 * upstream: condition/as/LoadServerJWKs.java
 */
export function loadServerJWKs(config: TestConfig): ServerKeys {
	const c: Condition = condition("LoadServerJWKs");
	const server = config["server"];
	const configured =
		server != null && typeof server === "object" && !Array.isArray(server)
			? (server as Record<string, unknown>)["jwks"]
			: undefined;
	if (configured == null) {
		c.failure("Couldn't find a JWK set in configuration");
	}
	// parse the JWKS to make sure it's valid
	try {
		const jwks = parseJWKSet(JSON.stringify(configured));
		const publicKeys = publicJwks(jwks);
		const privateKeys = privateJwks(jwks);
		const foundEncKeys = (privateKeys.keys as JWK[]).filter((key) => key["use"] == null || key["use"] === "enc");
		const encKeysJwks: Record<string, unknown> = foundEncKeys.length > 0 ? { keys: foundEncKeys } : {};
		c.success("Parsed public and private JWK sets", {
			server_public_jwks: publicKeys,
			server_jwks: privateKeys,
			server_encryption_keys: encKeysJwks,
		});
		return { publicJwks: publicKeys, jwks: privateKeys, encryptionKeys: { keys: foundEncKeys } as Jwks };
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Failure parsing JWK Set", e, { jwk_string: configured });
		}
		throw e;
	}
}

/**
 * A minimal FAPI 2 server JWKS: one PS256 RSA signing key with an explicit alg (so ExtractServerSigningAlg works
 * and AugmentRealJwksWithDecoys can generate decoys around it), and one RSA encryption key.
 *
 * upstream: condition/as/FAPI2GenerateServerJWKs.java
 */
export function fapi2GenerateServerJWKs(...requirements: string[]): ServerKeys {
	return generateServerJwks(
		"FAPI2GenerateServerJWKs",
		{
			numberOfRSASigningKeysWithNoAlg: 0,
			numberOfECCurveP256SigningKeysWithNoAlg: 0,
			numberOfECCurveSECP256KSigningKeysWithNoAlg: 0,
			numberOfOKPSigningKeysWithNoAlg: 0,
			numberOfPSSigningKeys: 1,
			numberOfRSAEncKeys: 1,
			numberOfECEncKeys: 0,
		},
		requirements,
	);
}

/** The FAPI algorithms a decoy is generated for (upstream AugmentRealJwksWithDecoys.FAPI_JWK_ALGORITHMS) */
const FAPI_JWK_ALGORITHMS = ["EdDSA", "PS256", "ES256"];

/** A fresh key for `alg` with the given kid (upstream AbstractGenerateKey.createJwkForAlg with keyID(kid)) */
async function decoyKey(alg: string, kid: string): Promise<JWK> {
	const key = await generateJwkForAlg(alg);
	key["kid"] = kid;
	return key;
}

/**
 * Adds "decoy" public keys with the real signing key's kid but the other FAPI algorithms to the published JWKS,
 * so a client must look keys up by kid, alg and kty together. The published set is the real key and its decoys
 * only; the keys with another `use` are left out (upstream rebuilds server_public_jwks from them).
 *
 * upstream: condition/client/AugmentRealJwksWithDecoys.java
 */
export async function augmentRealJwksWithDecoys(keys: ServerKeys, ...requirements: string[]): Promise<void> {
	const c: Condition = condition("AugmentRealJwksWithDecoys", ...requirements);
	let publicKeys: JWK[];
	try {
		// extract the real public JWKSet
		publicKeys = parseJWKSet(JSON.stringify(keys.jwks))
			.keys.map((k) => toPublicJWK(k))
			.filter((k): k is JWK => k != null);
	} catch (e) {
		c.failureFrom("Failed to parse server_jwks", e);
	}
	if (publicKeys.length === 0) {
		c.success("Skipping JWKS decoy generation for server_jwks with missing public keys.");
		return;
	}
	// try to find the public JWK used for signing
	const publicKeysForSigning = publicKeys.filter((k) => k["use"] === "sig");
	if (publicKeysForSigning.length === 0) {
		c.success("Skipping JWKS decoy generation for server_jwks with missing public keys of use=sig.");
		return;
	}
	const existingJwks = { keys: publicKeys };
	if (publicKeysForSigning.length !== 1) {
		// several keys: the JWKS must already contain keys with the same kid for all desired "decoy" algorithms
		const idToAlgs = new Map<string, Set<string>>();
		for (const key of publicKeysForSigning) {
			let algName = String(key["alg"]);
			if (algName === "Ed25519") {
				algName = "EdDSA";
			}
			const kid = String(key["kid"]);
			(idToAlgs.get(kid) ?? idToAlgs.set(kid, new Set()).get(kid))?.add(algName);
		}
		const kidsWithMissingFapiAlgorithms: Record<string, string[]> = {};
		for (const [kid, algs] of idToAlgs) {
			const missing = FAPI_JWK_ALGORITHMS.filter((a) => !algs.has(a));
			if (missing.length > 0) {
				kidsWithMissingFapiAlgorithms[kid] = missing;
			}
		}
		if (Object.keys(kidsWithMissingFapiAlgorithms).length > 0) {
			// UPSTREAM: logs a failure without throwing (the framework then fails the condition for not throwing)
			c.logFailure("Existing server_jwks contains multiple keys for use=sig, but desired JWK variant is missing", {
				jwks_ids_with_missing_fapi_algorithms: kidsWithMissingFapiAlgorithms,
			});
			return;
		}
		c.success(
			"Existing server_jwks already contains JWKs with the desired algorithm variants. Skipping generation of additional decoy JWKs.",
		);
		return;
	}
	// a single public key with use=sig: decoy keys with the same kid for the missing algorithms
	const publicKey = publicKeysForSigning[0];
	if (publicKey["alg"] == null) {
		c.logFailure("Public JWK with use=sig is missing alg information.", { kid: publicKey["kid"] ?? null, alg: null });
		return;
	}
	const kid = String(publicKey["kid"]);
	let keysWithDecoys: JWK[];
	switch (String(publicKey["alg"])) {
		case "ES256":
			keysWithDecoys = [await decoyKey("EdDSA", kid), publicKey, await decoyKey("PS256", kid)];
			break;
		case "EdDSA":
		case "Ed25519":
			// EdDSA and Ed25519 are the same curve/kty, so they're treated as the same "family" here
			keysWithDecoys = [await decoyKey("ES256", kid), publicKey, await decoyKey("PS256", kid)];
			break;
		case "PS256":
			keysWithDecoys = [await decoyKey("EdDSA", kid), publicKey, await decoyKey("ES256", kid)];
			break;
		default:
			c.failure("Invalid FAPI alg detected in JWK", { alg: publicKey["alg"] });
	}
	const publicJwksWithDecoys = getPublicJwksAsJsonObject({ keys: keysWithDecoys }) as Jwks;
	keys.publicJwks = publicJwksWithDecoys;
	c.success("Augmented JWKS with decoy keys.", { existingJwks, jwksWithDecoys: publicJwksWithDecoys });
}

/** An RSA key with no alg that signs the id_token of the alternate-alg module (upstream SetRsaAltServerJwks.altRsaKey) */
const ALT_RSA_KEY = {
	p: "vTcrfPZ9eZjIXN4LZYyKMXG1lvH5UJukZgQQ1UQYENHPoJWIvi9JD7MPMjjEwpvZcD6YGzaczxboEiihlHPiqM6Dw9yTMbX4Bw-GgyFhgkYrOd8fPgMAFZXI4zl5G6aSTsRHolAMVXvuKGBD7QV1LnU7ZZ9hv0XZOeLDCaVzpm8",
	kty: "RSA",
	q: "6VHXO7lyTJcniJGAPJ_5H2UHrknODXun-bKTelxWZcEvw8t2gJDvia5mbmor7RLbdg4c4BojdflvhJJVXlxOsgxHMJiFP2cjVoNktHkEmgHCqCplJUD98ZCK7hfC5LwJLQwszMCpDbYAlVSUAsWFyWczo0hC4Kv0QCwluqm9uEc",
	d: "Cldd48WZrS2FWFm1KpmKp73z_1HNwp2Y0UnLBhuTekuQ72UR5KsYZ0w3YtD5Kj2a8TukNvJTOhkqvT2i_y7ZN6FK5o5CBL6z5LNzuzNhIYQNqypBkVxTdfTD3ghqFCbpVHPwPgl_M1HheipjLCbsP8UuwJEWEHKPtI_0ZqrAQjdwk32LvF9kahhdaGpMeNoOcRM1BQxURrsLUjJm8fOZcz6gfjItd-8m6-VXoXDPDjCKnePi6Wh6QLbpDnuefPWrKLyo_p4EaZK_hCWWZFk0XeoEWgsVcG7piMae2mpesimiWeA1ncqkbfQNdI4bYIUt31iFDz-XBG0osSH8GoGHCQ",
	e: "AQAB",
	use: "sig",
	kid: "rsa-none-alt-arg",
	qi: "VzPxjxy_hoMSgrGMWYQLmPg0OT0gLbvyRDwFKLIPU_-pt4CKZBzzhk5NtQ9SpnPiWQ-z0D1TjHAV53CO5sJZEfevKXoTwsnBLmJwnFBq4BInXcl8PGt_5p_nx9HYxc3Lo0NU0oDSID-B3rh2fjXt3NvHJbbAHZZuaRdsw5PM1ZU",
	dp: "H_X3tI32N9nkzjr7ddW9agipAawxzrnblRfOuBdecUjfZ2KazHU0RCCcyoDoS28D1X_dNYuOBTT7UkXmtSq1-ImZnDXf7x-rm5W1xOSYkebEWmwj3Neo5fx9CFSm7lK-l-tzpikbTD04xz0rfBfV6VkIBWxcmHB19t8kzrZRyKU",
	dq: "DejOHwZgNQax2adq8LJMxL1eJtrJiO49RlqKBjppACnzMgX4K5P4Y8nc22pC8iA0qyYOPKHyST80kb-zjSuNmXm36MK-9tesOKUepM-uIYxHUYUtgHoOaY9HaQhLmx1GosPeC9rUeTfHcx-Wr0-dOTOI1YwiSIiXyBeZrDYgVFM",
	n: "rHO0Hvkwg8p9MMsTK9H2cWIVcuTXgqD9MQZnb48FM-tdmoMlPjU5WUg4N8h_4jdQ1ADgQACppuoJiXhDidN4aOiVjSso-SRjwWxKbq4TVvlNdzOCH-ligo4ftcJBLUWJJLD3I64BGG7KMoovEPFN89jR3VXD6RyKj4vaY706CaCkxZlGS9Mp8sGdT7zv5UjGKhh4-KRolRq9mId2mnleIvZBYyANxd0Rb861RY7g3O4DxWEA3xtxkSJrcBkDyY8IrKl0mxKldaR9rll4FmYoNZWzZqFoDfLzt7rYSiYOfXdt-QIlMlZthqVa3RJMM8L5MrRevoRVKjmulH1_KaXwyQ",
};

/**
 * An RSA key with no alg is added to the published keys as the alternate signing key (the id_token signed with
 * RS256 of the alternate-alg module). Returns the alternate key's private JWK set (upstream "server_alt_jwks").
 * UPSTREAM: the published set is rebuilt from the signing keys, so the decoys of AugmentRealJwksWithDecoys are lost.
 *
 * upstream: condition/as/SetRsaAltServerJwks.java
 */
export function setRsaAltServerJwks(keys: ServerKeys): Jwks {
	const c: Condition = condition("SetRsaAltServerJwks");
	// parse the JWKS to make sure it's valid
	try {
		const jwks = parseJWKSet(JSON.stringify(keys.jwks));
		const privateKeys = privateJwks(jwks);
		// Alt RSA signing key with alg NONE.
		const altPrivateKey = parseJWK(JSON.stringify(ALT_RSA_KEY));
		const publicKeys = getPublicJwksAsJsonObject({ keys: [...jwks.keys, altPrivateKey] }) as Jwks;
		keys.publicJwks = publicKeys;
		c.log("generated new alt RSA key configuration");
		const altJwks = privateJwks({ keys: [altPrivateKey] });
		c.success("Set alt server key", {
			server_public_jwks: publicKeys,
			server_jwks: privateKeys,
			server_alt_jwks: altJwks,
		});
		return altJwks;
	} catch (e) {
		if (e instanceof ParseException) {
			c.failureFrom("Failure parsing server_jwks JWK Set", e, { jwk_string: keys.jwks });
		}
		throw e;
	}
}
