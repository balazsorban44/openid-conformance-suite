import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CompactEncrypt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { parseJavaURI } from "./jdk/uri.ts";
import { JWKUtil, ParseException, type JWK, type JWKSet } from "./JWKUtil.ts";
import { JWTUtil, type JWT } from "./JWTUtil.ts";

/*
 * Pins the Nimbus replacement helpers that are about to be moved out of the conditions into src/util.
 *
 * parseSignedJWT (4 private copies) and selectJWSJwks (3 private copies) are module-private, so they are loaded by
 * "reflection": the condition's source with an extra `export { ... }`, type-stripped and imported as a data: URL
 * (its imports are rewritten to absolute URLs, so it shares every other module instance with this test).
 *
 * Differences between the copies today (decide deliberately when merging):
 *  - parseSignedJWT: no behavioural difference. AbstractVerifyJwsSignature tests `type === "encrypted"` first,
 *    the other three test `parts.length !== 3`; JWTUtil.parseJWT returns "encrypted" exactly for 5 parts, so every
 *    input gives the same result/message.
 *  - selectJWSJwks, kid: AbstractValidateJWKs uses any non-null header kid (a numeric kid then matches no key);
 *    AbstractVerifyJwsSignature and ValidateRequestObjectSignature ignore a non-string kid (all keys match).
 *  - selectJWSJwks, x5t#S256: ignored by AbstractValidateJWKs; AbstractVerifyJwsSignature compares the key's
 *    "x5t#S256" member (RSA/EC only); ValidateRequestObjectSignature also accepts the SHA-256 thumbprint of the
 *    key's first x5c certificate (not exercised here: no certificate generation without dependencies).
 *  - selectJWSJwks, OKP curves: alg Ed25519 -> AbstractValidateJWKs/AbstractVerifyJwsSignature only Ed25519 keys,
 *    ValidateRequestObjectSignature any OKP curve; alg Ed448 -> AbstractValidateJWKs Ed25519 and Ed448,
 *    AbstractVerifyJwsSignature only Ed448, ValidateRequestObjectSignature any OKP curve. EdDSA: both curves in all.
 *  - selectJWSJwks, output: ValidateRequestObjectSignature only returns RSA/EC/OKP/oct keys (the kty filter makes
 *    that equivalent to the others' "everything that is not oct is asymmetric").
 */

async function privateFunctions<T>(file: string, names: string[]): Promise<T> {
	const path = fileURLToPath(new URL(file, import.meta.url));
	const source =
		readFileSync(path, "utf8").replace(
			/from "([^"]+)"/g,
			(_m, spec: string) =>
				`from "${spec.startsWith(".") ? pathToFileURL(resolve(dirname(path), spec)).href : import.meta.resolve(spec)}"`,
		) + `\nexport { ${names.join(", ")} };\n`;
	const emitWarning = process.emitWarning;
	process.emitWarning = () => {}; // stripTypeScriptTypes is "experimental"
	let js: string;
	try {
		js = stripTypeScriptTypes(source, { mode: "strip" });
	} finally {
		process.emitWarning = emitWarning;
	}
	return (await import("data:text/javascript;base64," + Buffer.from(js).toString("base64"))) as T;
}

type ParseSignedJWT = { parseSignedJWT: (s: string) => JWT };
type SelectJWSJwks = { selectJWSJwks: (header: Record<string, unknown>, set: JWKSet) => JWK[] };

const PARSE_COPIES = [
	"../condition/client/AbstractVerifyJwsSignature.ts",
	"../condition/as/ValidateRequestObjectSignature.ts",
	"../condition/as/ValidateClientAssertionSignatureWithHMACAlgorithm.ts",
	"../condition/as/EnsureClientAssertionSignatureAlgorithmMatchesRegistered.ts",
];
const SELECT_COPIES = [
	"../condition/client/AbstractValidateJWKs.ts",
	"../condition/client/AbstractVerifyJwsSignature.ts",
	"../condition/as/ValidateRequestObjectSignature.ts",
];

function outcome(fn: () => JWT): unknown {
	try {
		const jwt = fn();
		return [jwt.type, jwt.header, jwt.parts.length];
	} catch (e) {
		assert.ok(e instanceof ParseException, String(e));
		return e.message;
	}
}

test("parseSignedJWT: all four copies", async () => {
	const secret = new Uint8Array(32).fill(7);
	const jws = await new SignJWT({ sub: "x" }).setProtectedHeader({ alg: "HS256", kid: "k" }).sign(secret);
	const jwe = await new CompactEncrypt(new TextEncoder().encode("{}"))
		.setProtectedHeader({ alg: "dir", enc: "A128GCM" })
		.encrypt(new Uint8Array(16));
	const cases: [string, unknown][] = [
		[jws, ["signed", { alg: "HS256", kid: "k" }, 3]],
		[
			" " + jws,
			"The jwt is invalid because at index 0 it contains the character   that is neither a '.' nor one permitted in unpadded base64url",
		],
		["eyJhbGciOiJub25lIn0.e30.", "Invalid JWS header: Not a JWS header"],
		[jwe, "Unexpected number of Base64URL parts, must be three"],
		["abc", "Invalid JWT serialization: Missing dot delimiter(s)"],
		["a.b", "Invalid unsecured/JWS/JWE header: Invalid JSON object"],
		[
			"a+b.c.d",
			"The jwt is invalid because at index 1 it contains the character + that is neither a '.' nor one permitted in unpadded base64url",
		],
		["e30.e30.sig", 'Missing "alg" in header JSON object'],
		["a.b.c.d.e.f", "Invalid unsecured/JWS/JWE header: Invalid JSON object"],
	];
	for (const file of PARSE_COPIES) {
		const { parseSignedJWT } = await privateFunctions<ParseSignedJWT>(file, ["parseSignedJWT"]);
		for (const [input, expected] of cases) {
			assert.deepEqual(
				outcome(() => parseSignedJWT(input)),
				expected,
				`${file}: ${input}`,
			);
		}
	}
});

async function jwk(alg: string, extra: Record<string, unknown>, priv = false): Promise<JWK> {
	const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
	return { ...(await exportJWK(priv ? privateKey : publicKey)), ...extra } as JWK;
}

const label = (k: JWK) => String(k["kid"]) + (k["d"] != null || k["k"] != null ? "*" : "");

test("selectJWSJwks: the three copies", async () => {
	const ed448 = generateKeyPairSync("ed448").publicKey.export({ format: "jwk" });
	const set: JWKSet = {
		keys: [
			await jwk("RS256", { kid: "r1", use: "sig", alg: "RS256", "x5t#S256": "T1" }, true),
			await jwk("RS256", { kid: "r2" }),
			await jwk("RS256", { kid: "r3", use: "enc" }),
			await jwk("ES256", { kid: "e1", alg: "ES256" }),
			await jwk("Ed25519", { kid: "o1" }, true),
			{ ...ed448, kid: "o2" } as JWK,
			{ kty: "oct", kid: "h1", k: "c2VjcmV0" } as JWK,
		],
	};
	// expected per copy: [AbstractValidateJWKs, AbstractVerifyJwsSignature, ValidateRequestObjectSignature]
	const all = ["r1", "r1*", "r2"];
	const cases: [Record<string, unknown>, string[][]][] = [
		[{ alg: "RS256" }, [all, all, all]],
		[{ alg: "RS256", kid: "r2" }, [["r2"], ["r2"], ["r2"]]],
		[{ alg: "RS256", kid: 7 }, [[], all, all]],
		[{ alg: "RS256", "x5t#S256": "T1" }, [all, ["r1", "r1*"], ["r1", "r1*"]]],
		[{ alg: "PS256" }, [["r2"], ["r2"], ["r2"]]],
		[{ alg: "ES256" }, [["e1"], ["e1"], ["e1"]]],
		[{ alg: "ES384" }, [[], [], []]],
		[
			{ alg: "EdDSA" },
			[
				["o1", "o1*", "o2"],
				["o1", "o1*", "o2"],
				["o1", "o1*", "o2"],
			],
		],
		[
			{ alg: "Ed25519" },
			[
				["o1", "o1*"],
				["o1", "o1*"],
				["o1", "o1*", "o2"],
			],
		],
		[{ alg: "Ed448" }, [["o1", "o1*", "o2"], ["o2"], ["o1", "o1*", "o2"]]],
		[{ alg: "HS256" }, [["h1*"], ["h1*"], ["h1*"]]],
		[{ alg: "HS256", kid: "r1" }, [[], [], []]],
		[{ alg: "none" }, [[], [], []]],
		[{ alg: "RSA-OAEP" }, [[], [], []]],
	];
	for (let i = 0; i < SELECT_COPIES.length; i++) {
		const { selectJWSJwks } = await privateFunctions<SelectJWSJwks>(SELECT_COPIES[i], ["selectJWSJwks"]);
		for (const [header, expected] of cases) {
			assert.deepEqual(
				selectJWSJwks(header, set).map(label),
				expected[i],
				`${SELECT_COPIES[i]}: ${JSON.stringify(header)}`,
			);
		}
		// the public copy of a private key carries no private members
		const [pub] = selectJWSJwks({ alg: "RS256", kid: "r1" }, set);
		assert.deepEqual(
			Object.keys(pub).filter((k) => ["d", "p", "q", "dp", "dq", "qi"].includes(k)),
			[],
		);
	}
});

test("parseJavaURI (java.net.URI)", () => {
	const ok: [string, [string | null, string | null, number, string | null]][] = [
		["https://example.com/cb", ["https", "example.com", -1, null]],
		["https://Example.COM:8443/cb?x=1#", ["https", "Example.COM", 8443, ""]],
		["https://example.com/cb#frag", ["https", "example.com", -1, "frag"]],
		["http://[::1]:80/", ["http", "[::1]", 80, null]],
		["http://127.0.0.1:3000/cb", ["http", "127.0.0.1", 3000, null]],
		["com.example.app:/callback", ["com.example.app", null, -1, null]],
		["urn:ietf:wg:oauth:2.0:oob", ["urn", null, -1, null]],
		["https://user:pw@host.example/x", ["https", "host.example", -1, null]],
		["https://exa_mple.com/", ["https", null, -1, null]], // registry-based authority
		["https://-bad.example/", ["https", null, -1, null]],
		["https://example.com:abc/", ["https", null, -1, null]],
		["https:///path", ["https", null, -1, null]],
		["", [null, null, -1, null]],
		["/relative/path", [null, null, -1, null]],
		["https://example.com/é", ["https", "example.com", -1, null]],
	];
	for (const [input, [scheme, host, port, fragment]] of ok) {
		assert.deepEqual(parseJavaURI(input), { scheme, host, port, fragment }, input);
	}
	const bad: [string, string][] = [
		["https://example.com/a b", "Illegal character in path at index 21"],
		["://x", "Expected scheme name at index 0"],
		["1https://x", "Illegal character in scheme name at index 0"],
		["https://example.com/%zz", "Malformed escape pair at index 20"],
		["https://exa mple.com/", "Illegal character in authority at index 8"],
		["https://[::zz]/", "Malformed IPv6 address at index 9"],
		["https://example.com/#a#b", "Illegal character in fragment at index 22"],
		["mailto:", "Expected scheme-specific part at index 7"],
	];
	for (const [input, reason] of bad) {
		assert.throws(() => parseJavaURI(input), { name: "URISyntaxException", message: `${reason}: ${input}` });
	}
});

test("JWKUtil: parseJWKSet, getSigningKey, toPublicJWK, isPrivate, selectAsymmetricJWSKey", async () => {
	const parseErrors: [string, string][] = [
		['{"foo":1}', 'Missing required "keys" member'],
		['{"keys":[1]}', 'The "keys" JSON array must contain JSON objects only'],
		['{"keys":[{"kty":"RSA"}]}', "Invalid JWK at position 0: The modulus value must not be null"],
	];
	for (const [input, message] of parseErrors) {
		assert.throws(
			() => JWKUtil.parseJWKSet(input),
			(e: unknown) => e instanceof ParseException && e.message === message,
		);
	}
	assert.deepEqual(JWKUtil.parseJWKSet('{"keys":[{"kty":"XYZ"}],"x":1}'), { x: 1, keys: [] }); // unknown kty dropped
	assert.deepEqual(JWKUtil.parseJWKSet({ keys: [{ k: "AAAA", use: "sig", kty: "oct" }] }), {
		keys: [{ kty: "oct", use: "sig", k: "AAAA" }], // Nimbus member order
	});

	assert.throws(() => JWKUtil.getSigningKey({ keys: [{ kty: "oct", k: "AAAA", use: "enc" }] }), {
		name: "InvalidArgumentException",
		message: "Did not find a key with 'use': 'sig' or no 'use' claim, no key available to sign jwt",
	});
	assert.throws(
		() =>
			JWKUtil.getSigningKey({
				keys: [
					{ kty: "oct", k: "AAAA", use: "sig" },
					{ kty: "oct", k: "AAAA" },
				],
			}),
		{
			message:
				"Expected only one signing JWK in the set. Please ensure the signing key is the only one in the jwks, or that other keys have a 'use' other than 'sig'.",
		},
	);

	const rsa = await jwk("RS256", { kid: "r" }, true);
	assert.equal(JWKUtil.isPrivate(rsa), true);
	const pub = JWKUtil.toPublicJWK(rsa) as JWK;
	assert.deepEqual(Object.keys(pub), ["kty", "e", "kid", "n"]); // Nimbus (HashMap) member order
	assert.equal(JWKUtil.isPrivate(pub), false);
	assert.equal(JWKUtil.toPublicJWK({ kty: "oct", k: "AAAA" }), null);
	assert.equal(JWKUtil.isPrivate({ kty: "oct" }), true);
	assert.deepEqual(JWKUtil.getPublicJwksAsJsonObject({ keys: [rsa, { kty: "oct", k: "AAAA" }] }), { keys: [pub] });

	const noUse = { kty: "RSA", kid: "a" };
	const sigNoAlg = { kty: "RSA", kid: "b", use: "sig" };
	const sigAlg = { kty: "RSA", kid: "c", use: "sig", alg: "RS256" };
	assert.equal(JWKUtil.selectAsymmetricJWSKey("RS256", [noUse, sigNoAlg, sigAlg])?.["kid"], "c");
	assert.equal(JWKUtil.selectAsymmetricJWSKey("PS256", [noUse, sigNoAlg, sigAlg])?.["kid"], "b");
	assert.equal(JWKUtil.selectAsymmetricJWSKey("RS256", [noUse])?.["kid"], "a");
	assert.equal(JWKUtil.selectAsymmetricJWSKey("ES256", [noUse, { kty: "EC", crv: "P-384" }]), null);
});

test("JWTUtil: parseJWT and jwtStringToJsonObjectForEnvironment", async () => {
	const secret = new Uint8Array(32).fill(1);
	const token = await new SignJWT({ aud: ["only"], exp: 1700000000, sub: "s" })
		.setProtectedHeader({ alg: "HS256", typ: "JWT" })
		.sign(secret);
	assert.deepEqual(JWTUtil.jwtStringToJsonObjectForEnvironment(token), {
		value: token,
		header: { typ: "JWT", alg: "HS256" },
		claims: { aud: "only", exp: 1700000000, sub: "s" },
	});
	const plain = JWTUtil.parseJWT("eyJhbGciOiJub25lIn0.e30.");
	assert.equal(plain.type, "plain");
	assert.equal(plain.signature, null);
	assert.throws(() => JWTUtil.parseJWT("a.b=.c"), {
		message:
			"The jwt is invalid because at index 3 it contains the character = that is neither a '.' nor one permitted in unpadded base64url",
	});
});
