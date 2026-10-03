import { expect, test } from "vitest";
import { javaReferences, referencesIn } from "./upstream-lock-symbols.ts";

test("javaReferences: paths after 'upstream:'; a bare file name is in the previous reference's directory", () => {
	expect(javaReferences("/** upstream: condition/client/ValidateIdTokenNonce.java */")).toEqual([
		"condition/client/ValidateIdTokenNonce.java",
	]);
	expect(
		javaReferences("upstream: sequence/X.java with condition/common/A.java, B.java and condition/client/C.java"),
	).toEqual(["sequence/X.java", "condition/common/A.java", "condition/common/B.java", "condition/client/C.java"]);
	expect(javaReferences("see condition/client/Elsewhere.java")).toEqual([]);
});

test("referencesIn: the function or test right after the comment; primary when the function ports the file", () => {
	const source = `
/** upstream: condition/client/A.java */
export function a(): void {}

/**
 * Not a reference: no marker
 */
function helper(): void {}

/** upstream: sequence/S.java with condition/client/A.java, B.java */
export async function group(): Promise<void> {}

/** upstream: Module.method: condition/client/C.java, condition/client/D.java */
function listing(): void {}

// upstream: openid/OIDCCServerTest.java
test("oidcc-server: does things", async () => {});
`;
	expect(referencesIn(source)).toEqual([
		["condition/client/A.java", "a", true],
		["sequence/S.java", "group", true],
		["condition/client/A.java", "group", false],
		["condition/client/B.java", "group", false],
		["condition/client/C.java", "listing", false],
		["condition/client/D.java", "listing", false],
		["openid/OIDCCServerTest.java", "oidcc-server", true],
	]);
});
