import { describe, expect, test } from "vitest";
import { ConditionFailed } from "../suite/conditions.ts";
import type { IncomingRequest } from "../suite/server.ts";
import { useTestLog } from "../suite/testing.ts";
import type { EmulatedOp, EmulatedOpOptions } from "./op.ts";
import { handleWebfingerRequest } from "./webfinger.ts";

const t = useTestLog("oidcc-client-test-discovery-webfinger-acct");

const op = (options: EmulatedOpOptions = {}) =>
	({
		testName: "oidcc-client-test-discovery-webfinger-acct",
		baseUrl: "https://localhost:8443/test/a/my-rp",
		options,
	}) as EmulatedOp;
const req = (resource?: string) =>
	({ query_string_params: resource == null ? {} : { resource } }) as unknown as IncomingRequest;
const issuer = "https://localhost:8443/test/a/my-rp/AbCdEfGhIj";

describe("webfinger", () => {
	test("an acct: or URL resource naming this test gets the issuer link", async () => {
		for (const resource of [
			"acct:my-rp.oidcc-client-test-discovery-webfinger-acct@localhost:8443",
			"https://localhost:8443/test/a/my-rp/oidcc-client-test-discovery-webfinger-acct",
		]) {
			const { response, webfinger } = await handleWebfingerRequest(op(), req(resource), issuer);
			expect(response.status).toBe(200);
			expect(webfinger).toEqual({
				subject: resource,
				links: [{ rel: "http://openid.net/specs/connect/1.0/issuer", href: issuer }],
			});
		}
		expect(t.entries().filter((e) => e.src === "CreateWebfingerResponse")).toHaveLength(2);
	});

	test("a resource that names no test of this server is answered without touching the test", async () => {
		expect((await handleWebfingerRequest(op(), req(), issuer)).response.status).toBe(400);
		expect((await handleWebfingerRequest(op(), req("mailto:someone@example.com"), issuer)).response.status).toBe(400);
		const other = await handleWebfingerRequest(op(), req("acct:other-rp.some-test@localhost"), issuer);
		expect(other.response.status).toBe(404);
		expect(t.entries()).toEqual([]);
	});

	test("another test's name or the wrong syntax for the module fails the test", async () => {
		await expect(
			handleWebfingerRequest(op(), req("acct:my-rp.oidcc-client-test-discovery-webfinger-url@localhost"), issuer),
		).rejects.toThrow(ConditionFailed);
		expect(t.entries().at(-1)?.msg).toContain("Test name in webfinger request does not match current test name");
		const acctOnly = op({
			validateWebfingerResource: (prefix) => {
				if (prefix !== "acct") {
					throw new ConditionFailed("x", "acct only", "FAILURE");
				}
			},
		});
		await expect(
			handleWebfingerRequest(
				acctOnly,
				req("https://localhost:8443/test/a/my-rp/oidcc-client-test-discovery-webfinger-acct"),
				issuer,
			),
		).rejects.toThrow("acct only");
	});
});
