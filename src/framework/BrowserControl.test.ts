import assert from "node:assert/strict";
import { test } from "node:test";
import { simpleMatch } from "./BrowserControl.ts";

test("simpleMatch follows Spring PatternMatchUtils", () => {
	assert.ok(simpleMatch("https://op/authorize*", "https://op/authorize?x=1"));
	assert.ok(simpleMatch("*/callback*", "http://localhost:1234/test/a/x/callback?code=1"));
	assert.ok(simpleMatch("*", "anything"));
	assert.ok(simpleMatch("exact", "exact"));
	assert.ok(!simpleMatch("exact", "exactly"));
	assert.ok(simpleMatch("a*b*c", "aXXbYYc"));
	assert.ok(!simpleMatch("a*b*c", "aXXbYY"));
	assert.ok(!simpleMatch(null, "x"));
});
