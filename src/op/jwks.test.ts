import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import { generateRsaJwk, publicJwks } from "../suite/jose.ts";
import { useTestLog } from "../suite/testing.ts";
import { verifyNewJwksHasNewSigningKey, verifyNewJwksStillHasOldSigningKey } from "./jwks.ts";

const t = useTestLog();

function keySet(...keys: { kid: string; use?: string }[]) {
	return publicJwks({ keys: keys.map(({ kid, use }) => ({ ...generateRsaJwk("RS256", use ?? "sig"), kid })) });
}

describe("key rotation of the OP", () => {
	test("a new key with a new kid and new key material, the old one retained", () => {
		const original = keySet({ kid: "old" });
		const rotated = { keys: [...original.keys, ...keySet({ kid: "new" }).keys] };
		verifyNewJwksHasNewSigningKey(original, rotated, "OIDCC-10.1.1");
		verifyNewJwksStillHasOldSigningKey(original, rotated, "OIDCC-10.1.1");
		expect(t.entries().map((e) => [e.src, e["result"], e["msg"]])).toEqual([
			["VerifyNewJwksHasNewSigningKey", "SUCCESS", "Found new keys"],
			["VerifyNewJwksStillHasOldSigningKey", "SUCCESS", "Some keys are in both the old and new JWKS"],
		]);
	});

	test("no rotation: no new signing key", () => {
		const original = keySet({ kid: "old" });
		expect(() => verifyNewJwksHasNewSigningKey(original, original)).toThrow(ConditionFailed);
		expect(t.entries().at(-1)).toMatchObject({ msg: "No new keys with 'use':'sig' (or no 'use') found" });
	});

	test("a new key that reuses a kid is not new", () => {
		const original = keySet({ kid: "same" });
		const reused = keySet({ kid: "same" });
		// the same kid with other key material is a different key set entry, but the kid must change too
		expect(() => verifyNewJwksHasNewSigningKey(original, reused)).toThrow(
			"One of the new keys uses the same kid as one of the original keys",
		);
	});

	test("keys that are not for signatures are ignored", () => {
		const original = keySet({ kid: "old" });
		const rotated = { keys: [...original.keys, ...keySet({ kid: "enc", use: "enc" }).keys] };
		expect(() => verifyNewJwksHasNewSigningKey(original, rotated)).toThrow(
			"No new keys with 'use':'sig' (or no 'use') found",
		);
	});

	test("the old key is gone: only a warning level check upstream", () => {
		expect(() => verifyNewJwksStillHasOldSigningKey(keySet({ kid: "old" }), keySet({ kid: "new" }))).toThrow(
			ConditionFailed,
		);
	});
});
