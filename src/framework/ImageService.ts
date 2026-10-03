import type { LogEntry, TestInstanceEventLog } from "./EventLog.ts";

/**
 * Port of the parts of info/ImageService.java the test framework uses.
 *
 * Upstream stores placeholders as log entries with an `upload` field; a placeholder is "filled" once the entry
 * also carries an image (`img`), a `page_source` or `image_no_longer_required`. We do the same against the
 * in-memory event log.
 */
export class ImageService {
	private readonly log: TestInstanceEventLog;

	constructor(log: TestInstanceEventLog) {
		this.log = log;
	}

	private placeholderEntries(): LogEntry[] {
		return this.log.entries.filter((e) => typeof e["upload"] === "string");
	}

	private isFilled(e: LogEntry): boolean {
		return e["img"] != null || e["page_source"] != null || e["image_no_longer_required"] === true;
	}

	getRemainingPlaceholders(_testId: string, _assumeAdmin = true): string[] {
		return this.placeholderEntries()
			.filter((e) => !this.isFilled(e))
			.map((e) => e["upload"] as string);
	}

	/** Placeholders filled with content that needs a human to look at it (not the ones marked no-longer-required) */
	getFilledPlaceholders(_testId: string, _assumeAdmin = true): string[] {
		return this.placeholderEntries()
			.filter((e) => this.isFilled(e) && e["image_no_longer_required"] !== true)
			.map((e) => e["upload"] as string);
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
		const entry = this.placeholderEntries().find((e) => e["upload"] === placeholder);
		if (!entry) {
			return null;
		}
		Object.assign(entry, update);
		return entry;
	}
}
