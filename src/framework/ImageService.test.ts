import assert from "node:assert/strict";
import { test } from "node:test";
import { TestInstanceEventLog } from "./EventLog.ts";
import { ImageService } from "./ImageService.ts";

test("placeholders are log entries with an upload field until filled", () => {
	const log = new TestInstanceEventLog("img");
	const images = new ImageService(log);
	log.log("A", { msg: "first", upload: "p1" });
	log.log("B", { msg: "not a placeholder" });
	log.log("C", { msg: "second", upload: "p2" });
	log.log("D", { msg: "third", upload: "p3" });
	log.log("E", { msg: "bad upload", upload: 1 });
	assert.deepEqual(images.getRemainingPlaceholders("img"), ["p1", "p2", "p3"]);
	assert.deepEqual(images.getFilledPlaceholders("img", true), []);

	const filled = images.fillPlaceholder("img", "p2", { page_source: "<html>", img: null }, true);
	assert.equal(filled, log.entries[2]);
	assert.deepEqual(Object.keys(filled ?? {}).slice(5), ["msg", "upload", "page_source", "img"]);
	images.fillPlaceholder("img", "p3", { image_no_longer_required: true });
	assert.equal(images.fillPlaceholder("img", "nope", { img: "x" }), null);

	assert.deepEqual(images.getRemainingPlaceholders("img", true), ["p1"]);
	assert.deepEqual(images.getFilledPlaceholders("img"), ["p2"]);
	images.fillPlaceholder("img", "p1", { img: "data:image/png;base64,AA==" });
	assert.deepEqual(images.getRemainingPlaceholders("img"), []);
	assert.deepEqual(images.getFilledPlaceholders("img"), ["p1", "p2"]);
});
