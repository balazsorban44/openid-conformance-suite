/**
 * The emulated OP's own keys: generated per test (upstream OIDCCGenerateServerJWKs and its variants), published at
 * `jwks_uri` (with five deliberately unusable keys), validated before the test starts.
 */
import { generateKeyPairSync, randomInt, randomUUID, type KeyObject } from "node:crypto";
import { checkDistinctKeyIdValueInServerJWKs, validateJwks } from "../op/jwks.ts";
import { condition, soft, type Condition } from "../suite/conditions.ts";
import { privateJwks, publicJwks, type JWK, type Jwks } from "../suite/jose.ts";
import { parseJWK } from "../suite/jose-jwk.ts";

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
