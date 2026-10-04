import { describe, expect, test } from "vitest";
import { useTestLog } from "./testing.ts";
import { waitForExpiry } from "./wait.ts";

const t = useTestLog();

describe("WaitForExpiry", () => {
	test("waits for the request_uri's expires_in seconds and logs the pause", async () => {
		await waitForExpiry(0);
		expect(t.entries().map((e) => [e.src, e["msg"]])).toEqual([
			["WaitForExpiry", "Pausing for 0 seconds"],
			["WaitForExpiry", "Woke up after 0 seconds sleep"],
		]);
	});

	test("fails without an expires_in", () => {
		expect(() => waitForExpiry(null)).toThrow("Missing key expires_in");
		expect(t.entries().at(-1)).toMatchObject({ src: "WaitForExpiry", result: "FAILURE" });
	});
});
