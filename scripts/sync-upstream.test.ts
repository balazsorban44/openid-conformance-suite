import { describe, expect, it } from "vitest";
import { renderReport, type ChangedSymbol } from "./sync-upstream.ts";

const range = {
	repo: "https://gitlab.com/openid/Conformance-suite.git",
	pinned: "1111111111111111111111111111111111111111",
	head: "2222222222222222222222222222222222222222",
	headDate: "2026-10-09T10:00:00+01:00",
	reportPath: "upstream-sync.md",
};

const changed: ChangedSymbol = {
	ts: "src/op/id-token.ts",
	symbol: "validateIdTokenNonce",
	java: "src/main/java/net/openid/conformance/condition/client/ValidateIdTokenNonce.java",
	deleted: false,
	added: 2,
	removed: 1,
	diff: "--- a\n+++ b\n-old\n+new\n+newer",
};

describe("renderReport", () => {
	it("lists every changed symbol with its upstream link and the compare range in body and report", () => {
		const deleted: ChangedSymbol = {
			...changed,
			symbol: "gone",
			java: "src/main/java/x/Gone.java",
			deleted: true,
			diff: "",
		};
		const { report, body } = renderReport([changed, deleted], range);
		for (const text of [report, body]) {
			expect(text).toContain("`src/op/id-token.ts#validateIdTokenNonce`");
			expect(text).toContain("+2 −1");
			expect(text).toContain("deleted upstream");
			expect(text).toContain(
				"/-/compare/1111111111111111111111111111111111111111...2222222222222222222222222222222222222222",
			);
			expect(text).toContain("2 ported symbols have upstream changes");
		}
		expect(report).toContain("```diff\n--- a\n+++ b\n-old\n+new\n+newer\n```");
		expect(body).not.toContain("```diff");
		expect(body).toContain("pnpm sync-upstream --pin");
	});

	it("cuts a long diff and points at the CLI for the rest", () => {
		const long = { ...changed, diff: Array.from({ length: 450 }, (_, i) => `+${i}`).join("\n") };
		const { report } = renderReport([long], range);
		expect(report).toContain("... 50 more lines: pnpm sync-upstream --diff src/op/id-token.ts#validateIdTokenNonce");
	});
});
