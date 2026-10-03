import type { LogEntry, TestInstanceEventLog } from "./EventLog.ts";

/**
 * Port of the parts of info/ImageService.java the test framework uses.
 *
 * Upstream stores placeholders as log entries with an `upload` field; a placeholder is "filled" once the entry
 * also carries an image (`img`), a `page_source` or `image_no_longer_required`. We do the same against the
 * in-memory event log. The test id and admin flag of the Java signatures are kept; there is one log per test.
 */
export class ImageService {
	private readonly log: TestInstanceEventLog;

	constructor(log: TestInstanceEventLog) {
		this.log = log;
	}

	getRemainingPlaceholders(_testId: string, _assumeAdmin = true): string[] {
		return this.placeholders((e) => !isFilled(e));
	}

	/** Placeholders filled with content that needs a human to look at it (not the ones marked no-longer-required) */
	getFilledPlaceholders(_testId: string, _assumeAdmin = true): string[] {
		return this.placeholders((e) => isFilled(e) && e["image_no_longer_required"] !== true);
	}

	/**
	 * Fill a placeholder with the given update (merged into the log entry). Returns the entry, or null if no such
	 * placeholder exists.
	 */
	fillPlaceholder(
		_testId: string,
		placeholder: string,
		update: Record<string, unknown>,
		_assumeAdmin = true,
	): LogEntry | null {
		const entry = this.log.entries.find((e) => typeof e["upload"] === "string" && e["upload"] === placeholder);
		return entry ? Object.assign(entry, update) : null;
	}

	private placeholders(filter: (e: LogEntry) => boolean): string[] {
		return this.log.entries
			.filter((e) => typeof e["upload"] === "string" && filter(e))
			.map((e) => e["upload"] as string);
	}
}

function isFilled(e: LogEntry): boolean {
	return e["img"] != null || e["page_source"] != null || e["image_no_longer_required"] === true;
}
