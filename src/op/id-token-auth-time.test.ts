import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import type { ParsedJwt } from "../suite/jose.ts";
import { useTestLog } from "../suite/testing.ts";
import {
	checkIdTokenAuthTimeClaimsSameIfPresent,
	checkIdTokenAuthTimeIsRecentIfPresent,
	checkSecondIdTokenAuthTimeIsLaterIfPresent,
} from "./id-token.ts";

const t = useTestLog();
const idToken = (claims: Record<string, unknown>): ParsedJwt => ({ value: "x", header: {}, claims });
const last = () => t.entries().at(-1);

describe("auth_time of two authorizations", () => {
	test("prompt=login: the second auth_time must be later than the first", () => {
		checkSecondIdTokenAuthTimeIsLaterIfPresent(idToken({ auth_time: 10 }), idToken({ auth_time: 20 }));
		expect(last()).toMatchObject({ result: "SUCCESS", msg: "auth_time is later in the second id_token" });
		expect(() =>
			checkSecondIdTokenAuthTimeIsLaterIfPresent(idToken({ auth_time: 10 }), idToken({ auth_time: 10 })),
		).toThrow(ConditionFailed);
		expect(String(last()?.["msg"])).toContain("incorrectly has the same auth_time");
		expect(() =>
			checkSecondIdTokenAuthTimeIsLaterIfPresent(idToken({ auth_time: 10 }), idToken({ auth_time: 5 })),
		).toThrow(ConditionFailed);
		expect(String(last()?.["msg"])).toContain("incorrectly has an earlier auth_time");
	});

	test("auth_time missing from either id_token is logged, not failed", () => {
		checkSecondIdTokenAuthTimeIsLaterIfPresent(idToken({}), idToken({ auth_time: 20 }));
		checkIdTokenAuthTimeClaimsSameIfPresent(idToken({ auth_time: 20 }), idToken({}));
		expect(t.entries().map((e) => e["result"])).toEqual([undefined, undefined]);
	});

	test("prompt=none: the auth_time must not change", () => {
		checkIdTokenAuthTimeClaimsSameIfPresent(idToken({ auth_time: 10 }), idToken({ auth_time: 10 }));
		expect(last()).toMatchObject({ result: "SUCCESS" });
		expect(() =>
			checkIdTokenAuthTimeClaimsSameIfPresent(idToken({ auth_time: 10 }), idToken({ auth_time: 11 })),
		).toThrow(ConditionFailed);
	});
});

describe("auth_time of a max_age=1 authorization", () => {
	test("is recent when within the 5 minute skew, an old one fails", () => {
		const now = Math.floor(Date.now() / 1000);
		checkIdTokenAuthTimeIsRecentIfPresent(idToken({ auth_time: now - 60 }));
		expect(last()).toMatchObject({ result: "SUCCESS", msg: "auth_time in id_token is recent" });
		expect(() => checkIdTokenAuthTimeIsRecentIfPresent(idToken({ auth_time: now - 3600 }))).toThrow(ConditionFailed);
	});
});
