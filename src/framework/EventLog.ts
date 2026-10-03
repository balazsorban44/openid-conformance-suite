import { randomInt } from "node:crypto";
import type { LogArgs } from "./DataUtils.ts";

/**
 * A single entry in the test log. Mirrors the documents upstream writes to MongoDB (EventLog.java):
 * every entry has _id, testId, src (source), time and the free-form fields of the logged map.
 */
export interface LogEntry {
	_id: string;
	testId: string;
	src: string;
	time: number;
	seq: number;
	[key: string]: unknown;
}

export type LogSink = (entry: LogEntry) => void;

let seq = 0;

/**
 * Port of logging/TestInstanceEventLog.java (and the parts of EventLog.java the port needs).
 *
 * A wrapper around an in-memory event log that supports blocks and remembers the test ID.
 */
export class TestInstanceEventLog {
	readonly testId: string;
	readonly entries: LogEntry[] = [];
	private readonly sink: LogSink | undefined;
	// a block identifier for a log entry
	private blockId: string | null = null;

	/** `sink` sees every entry as it is logged */
	constructor(testId: string, sink?: LogSink) {
		this.testId = testId;
		this.sink = sink;
	}

	/**
	 * log(source, msg) or log(source, map)
	 */
	log(source: string, msgOrMap: string | LogArgs): void {
		const map: LogArgs = typeof msgOrMap === "string" ? { msg: msgOrMap } : { ...msgOrMap };
		if (this.blockId != null) {
			map["blockId"] = this.blockId;
		}
		seq++;
		const entry: LogEntry = { _id: `${this.testId}-${seq}`, testId: this.testId, src: source, time: Date.now(), seq };
		for (const [k, v] of Object.entries(map)) {
			entry[k] = sanitise(v);
		}
		this.entries.push(entry);
		this.sink?.(entry);
	}

	/** Start a new log block and return its ID */
	startBlock(message?: string | null): string {
		// create a random six-character hex string that we can use as a CSS color code in the logs
		this.blockId = randomInt(256 * 256 * 256)
			.toString(16)
			.padStart(6, "0");
		const blockId = this.blockId;
		if (message) {
			this.log("-START-BLOCK-", { msg: message, startBlock: true });
		}
		return blockId;
	}

	/** end a log block and return the previous block ID */
	endBlock(): string | null {
		const oldBlock = this.blockId;
		this.blockId = null;
		return oldBlock;
	}

	/** Wraps the given block in a startBlock()... endBlock() sequence. */
	async runBlock(message: string | null, block: () => void | Promise<void>): Promise<string | null> {
		this.startBlock(message);
		let result: string | null;
		try {
			await block();
		} finally {
			result = this.endBlock();
		}
		return result;
	}
}

/**
 * Make a logged value JSON-safe: Sets become arrays, Errors become their message, Maps and Headers become objects.
 */
function sanitise(v: unknown): unknown {
	if (v instanceof Set || Array.isArray(v)) {
		return [...v].map(sanitise);
	}
	if (v instanceof Map || v instanceof Headers) {
		return sanitiseObject(Object.fromEntries(v));
	}
	if (v instanceof Error) {
		return v.message;
	}
	if (v instanceof URLSearchParams) {
		return v.toString();
	}
	if (typeof v === "bigint") {
		return Number(v);
	}
	if (typeof v === "object" && v !== null) {
		if (typeof (v as { toJSON?: unknown }).toJSON === "function") {
			return (v as { toJSON: () => unknown }).toJSON();
		}
		return sanitiseObject(v as LogArgs);
	}
	return v;
}

function sanitiseObject(map: LogArgs): LogArgs {
	const out: LogArgs = {};
	for (const [k, v] of Object.entries(map)) {
		out[k] = sanitise(v);
	}
	return out;
}
