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
	private sinks: LogSink[] = [];
	// a block identifier for a log entry
	private blockId: string | null = null;

	constructor(testId: string, sink?: LogSink) {
		this.testId = testId;
		if (sink) {
			this.sinks.push(sink);
		}
	}

	addSink(sink: LogSink): void {
		this.sinks.push(sink);
	}

	/**
	 * log(source, msg) or log(source, map)
	 */
	log(source: string, msgOrMap: string | LogArgs): void {
		let map: LogArgs;
		if (typeof msgOrMap === "string") {
			map = { msg: msgOrMap };
		} else {
			map = { ...msgOrMap };
		}
		if (this.blockId != null) {
			map["blockId"] = this.blockId;
		}
		const entry: LogEntry = {
			_id: `${this.testId}-${++seq}`,
			testId: this.testId,
			src: source,
			time: Date.now(),
			seq,
			...sanitise(map),
		};
		this.entries.push(entry);
		for (const sink of this.sinks) {
			sink(entry);
		}
	}

	private newBlockId(): string {
		// create a random six-character hex string that we can use as a CSS color code in the logs
		this.blockId = randomInt(256 * 256 * 256)
			.toString(16)
			.padStart(6, "0");
		return this.blockId;
	}

	/** Start a new log block and return its ID */
	startBlock(message?: string | null): string {
		const blockId = this.newBlockId();
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
 * Make a log map JSON-safe: Sets become arrays, Errors become their message, Maps become objects.
 */
function sanitise(map: LogArgs): LogArgs {
	const out: LogArgs = {};
	for (const [k, v] of Object.entries(map)) {
		out[k] = sanitiseValue(v);
	}
	return out;
}

function sanitiseValue(v: unknown): unknown {
	if (v instanceof Set) {
		return [...v].map(sanitiseValue);
	}
	if (v instanceof Map) {
		return sanitise(Object.fromEntries(v));
	}
	if (v instanceof Error) {
		return v.message;
	}
	if (v instanceof Headers) {
		const o: Record<string, string> = {};
		v.forEach((value, key) => {
			o[key] = value;
		});
		return o;
	}
	if (v instanceof URLSearchParams) {
		return v.toString();
	}
	if (typeof v === "bigint") {
		return Number(v);
	}
	if (Array.isArray(v)) {
		return v.map(sanitiseValue);
	}
	if (typeof v === "object" && v !== null) {
		if (typeof (v as { toJSON?: unknown }).toJSON === "function") {
			return (v as { toJSON: () => unknown }).toJSON();
		}
		return sanitise(v as LogArgs);
	}
	return v;
}
