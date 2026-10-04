import { describe, expect, it } from "vitest";
import { browsers, matrix, projects, runName } from "./projects.ts";

describe("matrix", () => {
	it("runs every project on chromium", () => {
		const onChromium = matrix()
			.filter((m) => m.browser === "chromium")
			.map((m) => m.project);
		expect(onChromium).toEqual(projects.map((p) => p.name));
	});

	it("runs the projects that list browsers on each of them, once", () => {
		const pairs = matrix().map((m) => `${m.project} ${m.browser}`);
		expect(new Set(pairs).size).toBe(pairs.length);
		for (const p of projects.filter((x) => x.browsers)) {
			expect(
				matrix()
					.filter((m) => m.project === p.name)
					.map((m) => m.browser),
			).toEqual([...browsers]);
		}
	});
});

describe("runName", () => {
	it("is the project's name on chromium and suffixed with the browser otherwise", () => {
		expect(runName("op-basic-dynamic", "chromium")).toBe("op-basic-dynamic");
		expect(runName("op-basic-dynamic", "chrome-mobile")).toBe("op-basic-dynamic-chrome-mobile");
	});
});
